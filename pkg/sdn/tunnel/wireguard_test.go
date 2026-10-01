//go:build !fips

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
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type mockWG struct {
	configs map[string]wgtypes.Config
	err     error
	closed  bool
}

func (m *mockWG) ConfigureDevice(name string, cfg wgtypes.Config) error {
	if m.err != nil {
		return m.err
	}
	if m.configs == nil {
		m.configs = map[string]wgtypes.Config{}
	}
	m.configs[name] = cfg
	return nil
}

func (m *mockWG) Close() error { m.closed = true; return nil }

func wgPeerPub() string {
	k, _ := wgtypes.GenerateKey()
	return k.PublicKey().String()
}

func wgConfig() TunnelConfig {
	return TunnelConfig{
		Name: "wg-mia", Transport: TransportWireGuard,
		Local: "198.51.100.4", Remote: "198.51.100.100", TunnelIP: "10.255.1.1/30", TunnelIPv6: "fd00:1::1/64",
		WireGuard: &WireGuardConfig{KeyRef: "kms://platform/tunnel/wg-mia", PeerPublicKey: wgPeerPub(), RemotePort: 51820, ListenPort: 51820},
	}
}

func wgKeys(cfg TunnelConfig) *mockKeys {
	k, _ := wgtypes.GeneratePrivateKey()
	return &mockKeys{keys: map[string][]byte{cfg.WireGuard.KeyRef: k[:]}}
}

func TestWireGuardConfig_Validate(t *testing.T) {
	cases := map[string]struct {
		mutate func(*TunnelConfig)
		reason string
	}{
		"missing section": {func(c *TunnelConfig) { c.WireGuard = nil }, "requires a wireguard section"},
		"missing key ref": {func(c *TunnelConfig) { c.WireGuard.KeyRef = "" }, "key-ref is required"},
		"bad peer key":    {func(c *TunnelConfig) { c.WireGuard.PeerPublicKey = "not-base64!" }, "peer-public-key"},
		"short peer key":  {func(c *TunnelConfig) { c.WireGuard.PeerPublicKey = base64.StdEncoding.EncodeToString([]byte("short")) }, "32-byte"},
		"bad listen port": {func(c *TunnelConfig) { c.WireGuard.ListenPort = 70000 }, "listen-port"},
		"no remote port":  {func(c *TunnelConfig) { c.WireGuard.RemotePort = 0 }, "remote-port"},
		"negative ka":     {func(c *TunnelConfig) { c.WireGuard.PersistentKeepalive = -1 }, "persistent-keepalive"},
		"ipsec section":   {func(c *TunnelConfig) { c.IPsec = &IPsecConfig{} }, "no ipsec section"},
		"carrier type":    {func(c *TunnelConfig) { c.Type = TunnelTypeGRE }, "takes no type"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := wgConfig()
			c.mutate(&cfg)
			err := cfg.Validate()
			var invalid *ErrInvalidTunnelConfig
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Contains(t, err.Error(), c.reason)
		})
	}
	valid := wgConfig()
	require.NoError(t, valid.Validate(), "wireguard needs no carrier type")
	assert.Equal(t, DefaultWireGuardKeepalive, valid.WireGuard.effectiveKeepalive())
	assert.True(t, wireGuardAvailable)
}

func TestWireGuardDeviceConfig(t *testing.T) {
	cfg := wgConfig()
	priv, _ := wgtypes.GeneratePrivateKey()
	dev, err := wireGuardDeviceConfig(cfg, priv[:])
	require.NoError(t, err)
	assert.Equal(t, priv, *dev.PrivateKey)
	assert.True(t, dev.ReplacePeers)
	require.Equal(t, 51820, *dev.ListenPort)
	require.Len(t, dev.Peers, 1)
	p := dev.Peers[0]
	assert.Equal(t, cfg.WireGuard.PeerPublicKey, p.PublicKey.String())
	assert.Equal(t, "198.51.100.100:51820", p.Endpoint.String())
	assert.Equal(t, DefaultWireGuardKeepalive, *p.PersistentKeepaliveInterval)
	assert.True(t, p.ReplaceAllowedIPs)
	require.Len(t, p.AllowedIPs, 2, "the tunnel's v4 and v6 nets")

	cfg.WireGuard.ListenPort = 0
	dev, err = wireGuardDeviceConfig(cfg, priv[:])
	require.NoError(t, err)
	assert.Nil(t, dev.ListenPort)

	_, err = wireGuardDeviceConfig(cfg, []byte("short"))
	var km *ErrKeyMaterial
	require.True(t, errors.As(err, &km))

	cfg.WireGuard.PeerPublicKey = "!!!"
	_, err = wireGuardDeviceConfig(cfg, priv[:])
	var invalid *ErrInvalidTunnelConfig
	require.True(t, errors.As(err, &invalid))
}

func TestManager_EnsureTunnel_WireGuard(t *testing.T) {
	mock := newMockNetlinkOps()
	cfg := wgConfig()
	keys := wgKeys(cfg)
	wg := &mockWG{}
	m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keys))
	m.wg = wg

	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))
	link, ok := mock.links[cfg.Name]
	require.True(t, ok)
	_, isWG := link.(*vnl.Wireguard)
	assert.True(t, isWG, "a kernel WireGuard link")
	require.Contains(t, wg.configs, cfg.Name)
	assert.Len(t, mock.addrs[cfg.Name], 2)
	assert.Equal(t, 1, keys.calls)

	// Rekey re-applies the device config with the re-resolved key.
	require.NoError(t, m.Rekey(context.Background(), cfg.Name))
	assert.Equal(t, 2, keys.calls)

	require.NoError(t, m.Close())
	assert.True(t, wg.closed)
	_, ok = mock.links[cfg.Name]
	assert.False(t, ok)
}

func TestManager_EnsureTunnel_WireGuardFailures(t *testing.T) {
	cfg := wgConfig()
	t.Run("no key provider", func(t *testing.T) {
		m := newManagerWithOps(testLogger(), newMockNetlinkOps())
		var kp *ErrKeyProviderRequired
		require.True(t, errors.As(m.EnsureTunnel(context.Background(), cfg), &kp))
	})
	t.Run("wrong key length", func(t *testing.T) {
		m := newManagerWithOps(testLogger(), newMockNetlinkOps(), WithKeyProvider(&mockKeys{keys: map[string][]byte{cfg.WireGuard.KeyRef: []byte("short")}}))
		m.wg = &mockWG{}
		var km *ErrKeyMaterial
		require.True(t, errors.As(m.EnsureTunnel(context.Background(), cfg), &km))
	})
	t.Run("configure fails removes the link", func(t *testing.T) {
		mock := newMockNetlinkOps()
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(wgKeys(cfg)))
		m.wg = &mockWG{err: errors.New("EPERM")}
		var cf *ErrTunnelCreateFailed
		require.True(t, errors.As(m.EnsureTunnel(context.Background(), cfg), &cf))
		_, ok := mock.links[cfg.Name]
		assert.False(t, ok)
	})
	t.Run("link add fails", func(t *testing.T) {
		mock := newMockNetlinkOps()
		mock.linkAddFn = func(vnl.Link) error { return errors.New("EEXIST") }
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(wgKeys(cfg)))
		m.wg = &mockWG{}
		require.Error(t, m.EnsureTunnel(context.Background(), cfg))
	})
	t.Run("addr add fails", func(t *testing.T) {
		mock := newMockNetlinkOps()
		mock.addrAddFn = func(vnl.Link, *vnl.Addr) error { return errors.New("EINVAL") }
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(wgKeys(cfg)))
		m.wg = &mockWG{}
		require.Error(t, m.EnsureTunnel(context.Background(), cfg))
		_, ok := mock.links[cfg.Name]
		assert.False(t, ok)
	})
	t.Run("set up fails", func(t *testing.T) {
		mock := newMockNetlinkOps()
		mock.linkSetUpFn = func(vnl.Link) error { return errors.New("EIO") }
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(wgKeys(cfg)))
		m.wg = &mockWG{}
		require.Error(t, m.EnsureTunnel(context.Background(), cfg))
	})
	t.Run("mtu fails", func(t *testing.T) {
		mock := newMockNetlinkOps()
		mock.linkSetMTUFn = func(vnl.Link, int) error { return errors.New("EIO") }
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(wgKeys(cfg)))
		m.wg = &mockWG{}
		require.Error(t, m.EnsureTunnel(context.Background(), cfg))
	})
	t.Run("rekey without a device", func(t *testing.T) {
		mock := newMockNetlinkOps()
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(wgKeys(cfg)))
		m.wg = &mockWG{}
		require.NoError(t, m.EnsureTunnel(context.Background(), cfg))
		m.wg = nil
		var rk *ErrRekeyFailed
		require.True(t, errors.As(m.Rekey(context.Background(), cfg.Name), &rk))
	})
	t.Run("rekey configure fails", func(t *testing.T) {
		mock := newMockNetlinkOps()
		wg := &mockWG{}
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(wgKeys(cfg)))
		m.wg = wg
		require.NoError(t, m.EnsureTunnel(context.Background(), cfg))
		wg.err = errors.New("EPERM")
		var rk *ErrRekeyFailed
		require.True(t, errors.As(m.Rekey(context.Background(), cfg.Name), &rk))
	})
}

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
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type mockWG struct {
	configs map[string]wgtypes.Config
	err     error
	closed  bool
	// devices is the kernel's WireGuard devices, read by Device; deviceErr
	// fails the read.
	devices   map[string]*wgtypes.Device
	deviceErr error
}

// Device returns a copy, as the kernel does: the caller zeroizes the key.
func (m *mockWG) Device(name string) (*wgtypes.Device, error) {
	if m.deviceErr != nil {
		return nil, m.deviceErr
	}
	device, ok := m.devices[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	read := *device
	read.Peers = append([]wgtypes.Peer(nil), device.Peers...)
	return &read, nil
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

// leftWireGuard puts the device EnsureTunnel would build for cfg into the
// mocks, up, addressed and keyed, as a killed datapath leaves it behind.
func leftWireGuard(t *testing.T, mock *mockNetlinkOps, wg *mockWG, cfg TunnelConfig, keys *mockKeys) (*vnl.Wireguard, *wgtypes.Device) {
	t.Helper()
	priv, err := wgtypes.NewKey(keys.keys[cfg.WireGuard.KeyRef])
	require.NoError(t, err)
	want, err := wireGuardDeviceConfig(cfg, priv[:])
	require.NoError(t, err)
	peer := want.Peers[0]
	device := &wgtypes.Device{
		Name: cfg.Name, Type: wgtypes.LinuxKernel, PrivateKey: priv, PublicKey: priv.PublicKey(), ListenPort: cfg.WireGuard.ListenPort,
		Peers: []wgtypes.Peer{{
			PublicKey: peer.PublicKey, Endpoint: peer.Endpoint,
			PersistentKeepaliveInterval: *peer.PersistentKeepaliveInterval, AllowedIPs: peer.AllowedIPs,
		}},
	}
	link := &vnl.Wireguard{LinkAttrs: vnl.LinkAttrs{Name: cfg.Name, MTU: cfg.effectiveMTU(), Flags: net.FlagUp}}
	mock.mu.Lock()
	mock.links[cfg.Name] = link
	mock.addrs[cfg.Name] = []vnl.Addr{tunnelAddr(t, cfg.TunnelIP), tunnelAddr(t, cfg.TunnelIPv6), tunnelAddr(t, "fe80::1/64")}
	mock.mu.Unlock()
	if wg.devices == nil {
		wg.devices = map[string]*wgtypes.Device{}
	}
	wg.devices[cfg.Name] = device
	return link, device
}

func TestManager_EnsureTunnel_AdoptsTheWireGuardDeviceAKilledDatapathLeft(t *testing.T) {
	cases := map[string]func(*TunnelConfig, *wgtypes.Device){
		"configured listen port": func(*TunnelConfig, *wgtypes.Device) {},
		"any port when none is configured": func(c *TunnelConfig, d *wgtypes.Device) {
			c.WireGuard.ListenPort = 0
			d.ListenPort = 41641
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			mock := newMockNetlinkOps()
			cfg := wgConfig()
			keys := wgKeys(cfg)
			wg := &mockWG{}
			left, device := leftWireGuard(t, mock, wg, cfg, keys)
			setup(&cfg, device)
			mock.linkDelFn = func(vnl.Link) error { return errors.New("an adopted device is never deleted") }
			mock.linkAddFn = func(vnl.Link) error { return errors.New("an adopted device is never recreated") }
			m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keys))
			m.wg = wg

			require.NoError(t, m.EnsureTunnel(context.Background(), cfg))

			link, err := mock.LinkByName(cfg.Name)
			require.NoError(t, err)
			assert.Same(t, left, link, "the device carrying traffic is the one kept")
			assert.Empty(t, wg.configs, "a device already as configured is not reconfigured")
			assert.Contains(t, m.tunnels, cfg.Name, "the adopted tunnel is managed from now on")
			assert.NotEqual(t, wgtypes.Key{}, device.PrivateKey, "the kernel's key is read back as a copy")
		})
	}
}

func TestManager_EnsureTunnel_RecreatesAWireGuardDeviceThatDiffers(t *testing.T) {
	cases := map[string]func(*testing.T, *vnl.Wireguard, *wgtypes.Device, *mockNetlinkOps){
		"private key": func(t *testing.T, _ *vnl.Wireguard, d *wgtypes.Device, _ *mockNetlinkOps) {
			other, err := wgtypes.GeneratePrivateKey()
			require.NoError(t, err)
			d.PrivateKey = other
		},
		"listen port": func(_ *testing.T, _ *vnl.Wireguard, d *wgtypes.Device, _ *mockNetlinkOps) { d.ListenPort = 51821 },
		"mtu":         func(_ *testing.T, l *vnl.Wireguard, _ *wgtypes.Device, _ *mockNetlinkOps) { l.MTU = 1500 },
		"down":        func(_ *testing.T, l *vnl.Wireguard, _ *wgtypes.Device, _ *mockNetlinkOps) { l.Flags = 0 },
		"extra addr": func(t *testing.T, l *vnl.Wireguard, _ *wgtypes.Device, m *mockNetlinkOps) {
			m.addrs[l.Name] = append(m.addrs[l.Name], tunnelAddr(t, "10.9.9.9/32"))
		},
		"not a WireGuard link": func(_ *testing.T, l *vnl.Wireguard, _ *wgtypes.Device, m *mockNetlinkOps) {
			m.links[l.Name] = &vnl.Dummy{LinkAttrs: l.LinkAttrs}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			mock := newMockNetlinkOps()
			cfg := wgConfig()
			keys := wgKeys(cfg)
			wg := &mockWG{}
			left, device := leftWireGuard(t, mock, wg, cfg, keys)
			mutate(t, left, device, mock)
			m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keys))
			m.wg = wg

			require.NoError(t, m.EnsureTunnel(context.Background(), cfg))

			link, err := mock.LinkByName(cfg.Name)
			require.NoError(t, err)
			assert.NotSame(t, left, link, "a device that differs in any field is replaced")
			require.Contains(t, wg.configs, cfg.Name)
			assert.True(t, wg.configs[cfg.Name].ReplacePeers, "the new device gets the whole config")
		})
	}
}

func TestManager_EnsureTunnel_ReconcilesAnAdoptedDevicesPeersByDiff(t *testing.T) {
	mock := newMockNetlinkOps()
	cfg := wgConfig()
	keys := wgKeys(cfg)
	wg := &mockWG{}
	left, device := leftWireGuard(t, mock, wg, cfg, keys)
	stale, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	device.Peers[0].Endpoint = &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}
	device.Peers = append(device.Peers, wgtypes.Peer{PublicKey: stale.PublicKey()})
	m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keys))
	m.wg = wg

	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))

	link, err := mock.LinkByName(cfg.Name)
	require.NoError(t, err)
	assert.Same(t, left, link, "the device is kept")
	require.Contains(t, wg.configs, cfg.Name)
	applied := wg.configs[cfg.Name]
	assert.False(t, applied.ReplacePeers, "peers are changed one by one, never replaced wholesale")
	assert.Nil(t, applied.PrivateKey, "the adopted device's key is left alone")
	assert.Nil(t, applied.ListenPort)
	require.Len(t, applied.Peers, 2)
	assert.Equal(t, wgtypes.PeerConfig{PublicKey: stale.PublicKey(), Remove: true}, applied.Peers[0])
	assert.Equal(t, cfg.WireGuard.PeerPublicKey, applied.Peers[1].PublicKey.String())
	assert.Equal(t, "198.51.100.100:51820", applied.Peers[1].Endpoint.String(), "the wanted peer is set in place")
	assert.False(t, applied.Peers[1].Remove)
}

func TestWireGuardPeerDiff(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	want, err := wireGuardDeviceConfig(wgConfig(), priv[:])
	require.NoError(t, err)
	wanted := want.Peers[0]
	installed := func() wgtypes.Peer {
		return wgtypes.Peer{
			PublicKey: wanted.PublicKey, Endpoint: wanted.Endpoint,
			PersistentKeepaliveInterval: *wanted.PersistentKeepaliveInterval, AllowedIPs: append([]net.IPNet(nil), wanted.AllowedIPs...),
		}
	}

	t.Run("a peer already as wanted is untouched", func(t *testing.T) {
		peer := installed()
		peer.AllowedIPs[0], peer.AllowedIPs[1] = peer.AllowedIPs[1], peer.AllowedIPs[0]
		assert.Empty(t, wireGuardPeerDiff([]wgtypes.Peer{peer}, want.Peers), "the order of allowed IPs does not matter")
	})

	differs := map[string]func(*wgtypes.Peer){
		"missing":       nil,
		"endpoint":      func(p *wgtypes.Peer) { p.Endpoint.Port = 51821 },
		"no endpoint":   func(p *wgtypes.Peer) { p.Endpoint = nil },
		"keepalive":     func(p *wgtypes.Peer) { p.PersistentKeepaliveInterval = time.Minute },
		"allowed IPs":   func(p *wgtypes.Peer) { p.AllowedIPs = p.AllowedIPs[:1] },
		"other network": func(p *wgtypes.Peer) { p.AllowedIPs[0].IP = net.IPv4(10, 9, 9, 0) },
	}
	for name, mutate := range differs {
		t.Run("sets a wanted peer whose "+name+" differs", func(t *testing.T) {
			var have []wgtypes.Peer
			if mutate != nil {
				peer := installed()
				peer.Endpoint = &net.UDPAddr{IP: peer.Endpoint.IP, Port: peer.Endpoint.Port}
				mutate(&peer)
				have = append(have, peer)
			}
			diff := wireGuardPeerDiff(have, want.Peers)
			require.Len(t, diff, 1)
			assert.Equal(t, wanted.PublicKey, diff[0].PublicKey)
			assert.False(t, diff[0].Remove)
			assert.Nil(t, diff[0].PresharedKey)
		})
	}

	t.Run("clears a preshared key the tunnel does not configure", func(t *testing.T) {
		peer := installed()
		peer.PresharedKey = priv
		diff := wireGuardPeerDiff([]wgtypes.Peer{peer}, want.Peers)
		require.Len(t, diff, 1)
		require.NotNil(t, diff[0].PresharedKey)
		assert.Equal(t, wgtypes.Key{}, *diff[0].PresharedKey)
	})

	t.Run("removes a peer nobody wants", func(t *testing.T) {
		diff := wireGuardPeerDiff([]wgtypes.Peer{installed(), {PublicKey: priv.PublicKey()}}, want.Peers)
		assert.Equal(t, []wgtypes.PeerConfig{{PublicKey: priv.PublicKey(), Remove: true}}, diff)
	})
}

func TestManager_EnsureTunnel_WireGuardAdoptionFails(t *testing.T) {
	cases := map[string]func(*mockNetlinkOps, *mockWG, *mockKeys){
		"reading the addresses": func(mock *mockNetlinkOps, _ *mockWG, _ *mockKeys) {
			mock.addrListFn = func(vnl.Link, int) ([]vnl.Addr, error) { return nil, errors.New("netlink busy") }
		},
		"resolving the key": func(_ *mockNetlinkOps, _ *mockWG, keys *mockKeys) { keys.err = errors.New("kms down") },
		"reading the device": func(_ *mockNetlinkOps, wg *mockWG, _ *mockKeys) {
			wg.deviceErr = errors.New("EPERM")
		},
		"reconciling the peers": func(_ *mockNetlinkOps, wg *mockWG, _ *mockKeys) {
			wg.devices["wg-mia"].Peers = nil
			wg.err = errors.New("EPERM")
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			mock := newMockNetlinkOps()
			cfg := wgConfig()
			keys := wgKeys(cfg)
			wg := &mockWG{}
			left, _ := leftWireGuard(t, mock, wg, cfg, keys)
			breakIt(mock, wg, keys)
			m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keys))
			m.wg = wg

			err := m.EnsureTunnel(context.Background(), cfg)

			var failed *ErrTunnelCreateFailed
			require.ErrorAs(t, err, &failed)
			assert.Equal(t, cfg.Name, failed.Name)
			assert.Empty(t, m.tunnels)
			link, lookupErr := mock.LinkByName(cfg.Name)
			require.NoError(t, lookupErr)
			assert.Same(t, left, link, "a device that could not be checked is left as it is")
		})
	}
}

func TestLinkMatches_WireGuard(t *testing.T) {
	cfg := wgConfig()
	up := vnl.LinkAttrs{Name: cfg.Name, MTU: cfg.effectiveMTU(), Flags: net.FlagUp}

	assert.True(t, linkMatches(&vnl.Wireguard{LinkAttrs: up}, cfg))
	assert.False(t, linkMatches(&vnl.Wireguard{LinkAttrs: up}, validGREConfig()), "a GRE tunnel is never a WireGuard link")
	assert.False(t, linkMatches(&vnl.Gretun{LinkAttrs: up}, cfg), "a WireGuard tunnel is never a GRE link")
}

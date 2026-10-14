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
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	vnl "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func clientConfig(t *testing.T) WireGuardClientConfig {
	t.Helper()
	priv, _, err := GenerateWireGuardKey()
	if err != nil {
		t.Fatal(err)
	}
	return WireGuardClientConfig{
		Name:          "vpn-wg0",
		PrivateKey:    priv,
		Address:       netip.MustParsePrefix("10.8.0.2/32"),
		PeerPublicKey: peerPub(t),
		PeerEndpoint:  netip.MustParseAddrPort("198.51.100.7:51820"),
		Routes:        []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00:20::/48")},
	}
}

func newTestClient(nl *mockNetlinkOps, wg *recordingWG) *WireGuardClient {
	return newWireGuardClientWithOps(nil, nl, func() (wgOps, error) { return wg, nil })
}

func TestGenerateWireGuardKey_PublicKeyDerivesFromPrivate(t *testing.T) {
	priv, pub, err := GenerateWireGuardKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := wgtypes.NewKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	want := key.PublicKey()
	if !bytes.Equal(pub, want[:]) {
		t.Fatal("public key does not derive from the private key")
	}
	again, _, err := GenerateWireGuardKey()
	if err != nil || bytes.Equal(priv, again) {
		t.Fatalf("a second key must differ: err=%v", err)
	}
}

// keyCapturingWG copies the private key at ConfigureDevice time: the config
// only points at Up's key copy, which is zeroized before Up returns.
type keyCapturingWG struct {
	recordingWG
	key wgtypes.Key
}

func (k *keyCapturingWG) ConfigureDevice(name string, cfg wgtypes.Config) error {
	if cfg.PrivateKey != nil {
		k.key = *cfg.PrivateKey
	}
	return k.recordingWG.ConfigureDevice(name, cfg)
}

func TestWireGuardClient_UpKeysAddressesAndRoutes(t *testing.T) {
	nl := newMockNetlinkOps()
	wg := &keyCapturingWG{}
	cfg := clientConfig(t)
	want, err := wgtypes.NewKey(cfg.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key := cfg.PrivateKey
	c := newWireGuardClientWithOps(nil, nl, func() (wgOps, error) { return wg, nil })
	if err := c.Up(cfg); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if wg.key != want {
		t.Fatal("the kernel was not keyed with the client key")
	}
	if !bytes.Equal(key, make([]byte, wireGuardKeyLen)) {
		t.Fatal("private key not zeroized after keying")
	}
	if len(wg.calls) != 1 || wg.closed != 1 {
		t.Fatalf("configure calls=%d closed=%d", len(wg.calls), wg.closed)
	}
	dev := wg.calls[0]
	if dev.PrivateKey == nil || *dev.PrivateKey != (wgtypes.Key{}) || !dev.ReplacePeers || len(dev.Peers) != 1 {
		t.Fatalf("device config = %+v (the in-process key copy must be zeroized)", dev)
	}
	p := dev.Peers[0]
	if !bytes.Equal(p.PublicKey[:], cfg.PeerPublicKey) || p.Endpoint.String() != "198.51.100.7:51820" ||
		*p.PersistentKeepaliveInterval != DefaultWireGuardKeepalive || !p.ReplaceAllowedIPs {
		t.Fatalf("peer = %+v", p)
	}
	if len(p.AllowedIPs) != 2 || p.AllowedIPs[0].String() != "10.20.0.0/16" || p.AllowedIPs[1].String() != "fd00:20::/48" {
		t.Fatalf("allowed = %v", p.AllowedIPs)
	}
	link, ok := nl.links["vpn-wg0"]
	if !ok || link.Type() != wireGuardLinkType || link.Attrs().MTU != DefaultMTU || link.Attrs().OperState != vnl.OperUp {
		t.Fatalf("link = %+v", link)
	}
	if len(nl.addrs["vpn-wg0"]) != 1 || nl.addrs["vpn-wg0"][0].IPNet.String() != "10.8.0.2/32" {
		t.Fatalf("addresses = %v", nl.addrs["vpn-wg0"])
	}
	if len(nl.routes) != 2 || nl.routes[0].Dst.String() != "10.20.0.0/16" || nl.routes[1].Dst.String() != "fd00:20::/48" {
		t.Fatalf("routes = %v", nl.routes)
	}
}

func TestWireGuardClient_CustomMTUAndKeepalive(t *testing.T) {
	nl := newMockNetlinkOps()
	wg := &recordingWG{}
	cfg := clientConfig(t)
	cfg.MTU = 1380
	cfg.Keepalive = 10 * time.Second
	if err := newTestClient(nl, wg).Up(cfg); err != nil {
		t.Fatal(err)
	}
	if nl.links["vpn-wg0"].Attrs().MTU != 1380 || *wg.calls[0].Peers[0].PersistentKeepaliveInterval != 10*time.Second {
		t.Fatalf("mtu=%d keepalive=%v", nl.links["vpn-wg0"].Attrs().MTU, *wg.calls[0].Peers[0].PersistentKeepaliveInterval)
	}
}

func TestWireGuardClient_UpRefusesInvalidConfig(t *testing.T) {
	cases := map[string]struct {
		mutate func(*WireGuardClientConfig)
		check  func(error) bool
	}{
		"empty name":      {func(c *WireGuardClientConfig) { c.Name = "" }, isInvalidConfig("device name")},
		"long name":       {func(c *WireGuardClientConfig) { c.Name = strings.Repeat("w", 16) }, isInvalidConfig("device name")},
		"short key":       {func(c *WireGuardClientConfig) { c.PrivateKey = []byte("short") }, isKeyMaterial},
		"short peer key":  {func(c *WireGuardClientConfig) { c.PeerPublicKey = []byte("short") }, isPeerInvalid},
		"no endpoint":     {func(c *WireGuardClientConfig) { c.PeerEndpoint = netip.AddrPort{} }, isInvalidConfig("peer endpoint")},
		"endpoint port 0": {func(c *WireGuardClientConfig) { c.PeerEndpoint = netip.MustParseAddrPort("198.51.100.7:0") }, isInvalidConfig("peer endpoint")},
		"no address":      {func(c *WireGuardClientConfig) { c.Address = netip.Prefix{} }, isInvalidConfig("address")},
		"no routes":       {func(c *WireGuardClientConfig) { c.Routes = nil }, isInvalidConfig("at least one route")},
		"bad route":       {func(c *WireGuardClientConfig) { c.Routes = []netip.Prefix{{}} }, isInvalidConfig("route prefix")},
		"route over endpoint": {func(c *WireGuardClientConfig) {
			c.Routes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		}, isInvalidConfig("covers the peer endpoint")},
		"mtu":       {func(c *WireGuardClientConfig) { c.MTU = 9 }, isInvalidConfig("MTU")},
		"keepalive": {func(c *WireGuardClientConfig) { c.Keepalive = -time.Second }, isInvalidConfig("keepalive")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			nl := newMockNetlinkOps()
			wg := &recordingWG{}
			cfg := clientConfig(t)
			key := cfg.PrivateKey
			tc.mutate(&cfg)
			err := newTestClient(nl, wg).Up(cfg)
			if !tc.check(err) {
				t.Fatalf("err = %v", err)
			}
			if len(nl.links) != 0 || len(wg.calls) != 0 {
				t.Fatal("a refused config touched the kernel")
			}
			if name != "short key" && !bytes.Equal(key, make([]byte, wireGuardKeyLen)) {
				t.Fatal("private key not zeroized after a refusal")
			}
		})
	}
}

func TestWireGuardClient_FailedBringUpLeavesNothingBehind(t *testing.T) {
	boom := errors.New("boom")
	for name, arm := range map[string]func(*mockNetlinkOps, *recordingWG){
		"lookup": func(nl *mockNetlinkOps, _ *recordingWG) {
			nl.linkByNameFn = func(string) (vnl.Link, error) { return nil, boom }
		},
		"configure": func(_ *mockNetlinkOps, wg *recordingWG) { wg.err = boom },
		"mtu":       func(nl *mockNetlinkOps, _ *recordingWG) { nl.linkSetMTUFn = func(vnl.Link, int) error { return boom } },
		"address": func(nl *mockNetlinkOps, _ *recordingWG) {
			nl.addrAddFn = func(vnl.Link, *vnl.Addr) error { return boom }
		},
		"set up": func(nl *mockNetlinkOps, _ *recordingWG) { nl.linkSetUpFn = func(vnl.Link) error { return boom } },
		"second route": func(nl *mockNetlinkOps, _ *recordingWG) {
			calls := 0
			nl.routeReplaceFn = func(r *vnl.Route) error {
				calls++
				if calls == 2 {
					return boom
				}
				nl.routes = append(nl.routes, *r)
				return nil
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			nl := newMockNetlinkOps()
			wg := &recordingWG{}
			arm(nl, wg)
			cfg := clientConfig(t)
			key := cfg.PrivateKey
			err := newTestClient(nl, wg).Up(cfg)
			var cf *ErrTunnelCreateFailed
			if !errors.As(err, &cf) || !errors.Is(err, boom) {
				t.Fatalf("err = %v", err)
			}
			if _, ok := nl.links["vpn-wg0"]; ok {
				t.Fatal("link not rolled back")
			}
			if wg.closed != 1 {
				t.Fatalf("control socket closed %d times", wg.closed)
			}
			if !bytes.Equal(key, make([]byte, wireGuardKeyLen)) {
				t.Fatal("private key not zeroized after a failed bring-up")
			}
		})
	}
	t.Run("link add", func(t *testing.T) {
		nl := newMockNetlinkOps()
		nl.linkAddFn = func(vnl.Link) error { return boom }
		wg := &recordingWG{}
		var cf *ErrTunnelCreateFailed
		if err := newTestClient(nl, wg).Up(clientConfig(t)); !errors.As(err, &cf) || !errors.Is(err, boom) || wg.closed != 1 {
			t.Fatalf("err = %v closed=%d", err, wg.closed)
		}
	})
	t.Run("control socket", func(t *testing.T) {
		nl := newMockNetlinkOps()
		c := newWireGuardClientWithOps(nil, nl, func() (wgOps, error) { return nil, boom })
		var cf *ErrTunnelCreateFailed
		if err := c.Up(clientConfig(t)); !errors.As(err, &cf) || len(nl.links) != 0 {
			t.Fatalf("err = %v links=%d", err, len(nl.links))
		}
	})
}

func TestWireGuardClient_DownRemovesRoutesAndDevice(t *testing.T) {
	nl := newMockNetlinkOps()
	c := newTestClient(nl, &recordingWG{})
	if err := c.Up(clientConfig(t)); err != nil {
		t.Fatal(err)
	}
	var deleted []string
	nl.routeDelFn = func(r *vnl.Route) error {
		deleted = append(deleted, r.Dst.String())
		return nil
	}
	if err := c.Down("vpn-wg0"); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if len(deleted) != 2 || deleted[0] != "10.20.0.0/16" || deleted[1] != "fd00:20::/48" {
		t.Fatalf("routes deleted = %v", deleted)
	}
	if _, ok := nl.links["vpn-wg0"]; ok {
		t.Fatal("device left behind")
	}
}

func TestWireGuardClient_DownErrors(t *testing.T) {
	boom := errors.New("boom")
	t.Run("already gone", func(t *testing.T) {
		nl := newMockNetlinkOps()
		nl.linkByNameFn = func(string) (vnl.Link, error) { return nil, vnl.LinkNotFoundError{} }
		if err := newTestClient(nl, &recordingWG{}).Down("vpn-wg0"); err != nil {
			t.Fatalf("Down of a missing device = %v", err)
		}
	})
	t.Run("not wireguard", func(t *testing.T) {
		nl := newMockNetlinkOps()
		if err := nl.LinkAdd(&vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth0"}}); err != nil {
			t.Fatal(err)
		}
		var rf *ErrTunnelRemoveFailed
		var invalid *ErrInvalidTunnelConfig
		err := newTestClient(nl, &recordingWG{}).Down("eth0")
		if !errors.As(err, &rf) || !errors.As(err, &invalid) {
			t.Fatalf("err = %v", err)
		}
		if _, ok := nl.links["eth0"]; !ok {
			t.Fatal("a non-WireGuard link was removed")
		}
	})
	for name, arm := range map[string]func(*mockNetlinkOps){
		"lookup":       func(nl *mockNetlinkOps) { nl.linkByNameFn = func(string) (vnl.Link, error) { return nil, boom } },
		"route delete": func(nl *mockNetlinkOps) { nl.routeDelFn = func(*vnl.Route) error { return boom } },
		"link delete":  func(nl *mockNetlinkOps) { nl.linkDelFn = func(vnl.Link) error { return boom } },
	} {
		t.Run(name, func(t *testing.T) {
			nl := newMockNetlinkOps()
			c := newTestClient(nl, &recordingWG{})
			if err := c.Up(clientConfig(t)); err != nil {
				t.Fatal(err)
			}
			arm(nl)
			var rf *ErrTunnelRemoveFailed
			if err := c.Down("vpn-wg0"); !errors.As(err, &rf) || !errors.Is(err, boom) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func isInvalidConfig(reason string) func(error) bool {
	return func(err error) bool {
		var invalid *ErrInvalidTunnelConfig
		return errors.As(err, &invalid) && strings.Contains(invalid.Reason, reason)
	}
}

func isKeyMaterial(err error) bool {
	var km *ErrKeyMaterial
	return errors.As(err, &km)
}

func isPeerInvalid(err error) bool {
	var invalid *ErrPeerInvalid
	return errors.As(err, &invalid)
}

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
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	vnl "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// recordingWG records every ConfigureDevice call in order, which the
// per-peer hub semantics need (mockWG keeps only the last config).
type recordingWG struct {
	calls  []wgtypes.Config
	err    error
	closed int
}

func (r *recordingWG) ConfigureDevice(_ string, cfg wgtypes.Config) error {
	if r.err != nil {
		return r.err
	}
	r.calls = append(r.calls, cfg)
	return nil
}

func (r *recordingWG) Close() error { r.closed++; return nil }

func hubConfig() WireGuardHubConfig {
	return WireGuardHubConfig{
		Name: "wg-vpn0", KeyRef: "kms://platform/vpn/wireguard", ListenPort: 51820,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/24")},
	}
}

func hubKeys(t *testing.T, cfg WireGuardHubConfig) (*mockKeys, wgtypes.Key) {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &mockKeys{keys: map[string][]byte{cfg.KeyRef: append([]byte(nil), k[:]...)}}, k
}

func newTestHub(t *testing.T) (*WireGuardHub, *mockNetlinkOps, *recordingWG, wgtypes.Key) {
	t.Helper()
	cfg := hubConfig()
	keys, priv := hubKeys(t, cfg)
	nl := newMockNetlinkOps()
	wg := &recordingWG{}
	hub, err := newWireGuardHubWithOps(slog.Default(), cfg, keys, nl, wg)
	if err != nil {
		t.Fatal(err)
	}
	return hub, nl, wg, priv
}

func peerPub(t *testing.T) []byte {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey()
	return pub[:]
}

func TestWireGuardHub_UpKeysDeviceAndKeepsOnlyPublicKey(t *testing.T) {
	hub, nl, wg, priv := newTestHub(t)
	if hub.PublicKey() != nil {
		t.Fatal("public key before Up")
	}
	if err := hub.Up(context.Background()); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if len(wg.calls) != 1 {
		t.Fatalf("configure calls = %d", len(wg.calls))
	}
	dev := wg.calls[0]
	if dev.PrivateKey == nil || *dev.PrivateKey != priv || !dev.ReplacePeers || dev.ListenPort == nil || *dev.ListenPort != 51820 {
		t.Fatalf("device config = %+v", dev)
	}
	want := priv.PublicKey()
	if !bytes.Equal(hub.PublicKey(), want[:]) {
		t.Fatal("public key does not derive from the private key")
	}
	if hub.ListenPort() != 51820 {
		t.Fatalf("listen port = %d", hub.ListenPort())
	}
	link := nl.links["wg-vpn0"]
	if _, ok := link.(*vnl.Wireguard); !ok || link.Attrs().MTU != DefaultMTU {
		t.Fatalf("link = %T mtu=%d", link, link.Attrs().MTU)
	}
	if len(nl.addrs["wg-vpn0"]) != 1 || nl.addrs["wg-vpn0"][0].IPNet.String() != "10.9.0.1/24" {
		t.Fatalf("addresses = %v", nl.addrs["wg-vpn0"])
	}
	// A second Up is a no-op.
	if err := hub.Up(context.Background()); err != nil || len(wg.calls) != 1 {
		t.Fatalf("second Up: err=%v calls=%d", err, len(wg.calls))
	}
}

func TestWireGuardHub_SetAndRemovePeerTouchOnlyThatPeer(t *testing.T) {
	hub, _, wg, _ := newTestHub(t)
	if err := hub.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	pub := peerPub(t)
	lease := netip.MustParsePrefix("10.9.0.23/32")
	if err := hub.SetPeer(context.Background(), pub, []netip.Prefix{lease}); err != nil {
		t.Fatalf("SetPeer: %v", err)
	}
	set := wg.calls[1]
	if set.ReplacePeers || set.PrivateKey != nil || len(set.Peers) != 1 {
		t.Fatalf("SetPeer must not replace peers or rekey: %+v", set)
	}
	p := set.Peers[0]
	if !bytes.Equal(p.PublicKey[:], pub) || !p.ReplaceAllowedIPs || p.Remove || len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != "10.9.0.23/32" {
		t.Fatalf("peer = %+v", p)
	}
	if err := hub.RemovePeer(context.Background(), pub); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	rm := wg.calls[2]
	if rm.ReplacePeers || len(rm.Peers) != 1 || !rm.Peers[0].Remove || !bytes.Equal(rm.Peers[0].PublicKey[:], pub) {
		t.Fatalf("remove = %+v", rm)
	}
}

func TestWireGuardHub_PeerValidation(t *testing.T) {
	hub, _, _, _ := newTestHub(t)
	if err := hub.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cases := map[string]func() error{
		"short key": func() error {
			return hub.SetPeer(ctx, []byte("short"), []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")})
		},
		"no allowed":      func() error { return hub.SetPeer(ctx, peerPub(t), nil) },
		"invalid allowed": func() error { return hub.SetPeer(ctx, peerPub(t), []netip.Prefix{{}}) },
		"remove short":    func() error { return hub.RemovePeer(ctx, nil) },
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			var invalid *ErrPeerInvalid
			if err := call(); !errors.As(err, &invalid) {
				t.Fatalf("err = %v, want ErrPeerInvalid", err)
			}
		})
	}
}

func TestWireGuardHub_PeerBeforeUpAndKernelRefusal(t *testing.T) {
	hub, _, wg, _ := newTestHub(t)
	pub := peerPub(t)
	var notUp *ErrDeviceNotUp
	if err := hub.SetPeer(context.Background(), pub, []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}); !errors.As(err, &notUp) {
		t.Fatalf("SetPeer before Up = %v", err)
	}
	if err := hub.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	wg.err = errors.New("kernel says no")
	var failed *ErrPeerConfigureFailed
	if err := hub.SetPeer(context.Background(), pub, []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}); !errors.As(err, &failed) {
		t.Fatalf("SetPeer with kernel refusal = %v", err)
	}
	if err := hub.RemovePeer(context.Background(), pub); !errors.As(err, &failed) {
		t.Fatalf("RemovePeer with kernel refusal = %v", err)
	}
}

func TestWireGuardHub_UpFailuresRollBack(t *testing.T) {
	boom := errors.New("boom")
	t.Run("key provider fails", func(t *testing.T) {
		cfg := hubConfig()
		nl := newMockNetlinkOps()
		hub, err := newWireGuardHubWithOps(nil, cfg, &mockKeys{err: boom}, nl, &recordingWG{})
		if err != nil {
			t.Fatal(err)
		}
		var km *ErrKeyMaterial
		if err := hub.Up(context.Background()); !errors.As(err, &km) {
			t.Fatalf("err = %v", err)
		}
		if len(nl.links) != 0 {
			t.Fatal("link created without a key")
		}
	})
	t.Run("short key", func(t *testing.T) {
		cfg := hubConfig()
		hub, err := newWireGuardHubWithOps(nil, cfg, &mockKeys{keys: map[string][]byte{cfg.KeyRef: []byte("short")}}, newMockNetlinkOps(), &recordingWG{})
		if err != nil {
			t.Fatal(err)
		}
		var km *ErrKeyMaterial
		if err := hub.Up(context.Background()); !errors.As(err, &km) {
			t.Fatalf("err = %v", err)
		}
	})
	for name, arm := range map[string]func(*mockNetlinkOps, *recordingWG){
		"link add": func(nl *mockNetlinkOps, _ *recordingWG) { nl.linkAddFn = func(vnl.Link) error { return boom } },
		"lookup": func(nl *mockNetlinkOps, _ *recordingWG) {
			nl.linkByNameFn = func(string) (vnl.Link, error) { return nil, boom }
		},
		"configure": func(_ *mockNetlinkOps, wg *recordingWG) { wg.err = boom },
		"mtu":       func(nl *mockNetlinkOps, _ *recordingWG) { nl.linkSetMTUFn = func(vnl.Link, int) error { return boom } },
		"address": func(nl *mockNetlinkOps, _ *recordingWG) {
			nl.addrAddFn = func(vnl.Link, *vnl.Addr) error { return boom }
		},
		"set up": func(nl *mockNetlinkOps, _ *recordingWG) { nl.linkSetUpFn = func(vnl.Link) error { return boom } },
	} {
		t.Run(name, func(t *testing.T) {
			hub, nl, wg, _ := newTestHub(t)
			arm(nl, wg)
			err := hub.Up(context.Background())
			var cf *ErrTunnelCreateFailed
			if !errors.As(err, &cf) || !errors.Is(err, boom) {
				t.Fatalf("err = %v", err)
			}
			if _, ok := nl.links["wg-vpn0"]; ok {
				t.Fatal("link not rolled back")
			}
			if hub.PublicKey() != nil {
				t.Fatal("public key kept after a failed Up")
			}
		})
	}
}

func TestWireGuardHub_Down(t *testing.T) {
	hub, nl, wg, _ := newTestHub(t)
	if err := hub.Down(); err != nil {
		t.Fatalf("Down before Up: %v", err)
	}
	if err := hub.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := hub.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if _, ok := nl.links["wg-vpn0"]; ok || wg.closed != 1 || hub.PublicKey() != nil {
		t.Fatalf("Down left state: link=%v closed=%d key=%v", ok, wg.closed, hub.PublicKey())
	}
	if err := hub.Down(); err != nil || wg.closed != 1 {
		t.Fatalf("second Down: %v (closed %d)", err, wg.closed)
	}
	t.Run("link del fails", func(t *testing.T) {
		hub, nl, _, _ := newTestHub(t)
		if err := hub.Up(context.Background()); err != nil {
			t.Fatal(err)
		}
		nl.linkDelFn = func(vnl.Link) error { return errors.New("busy") }
		var rf *ErrTunnelRemoveFailed
		if err := hub.Down(); !errors.As(err, &rf) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestWireGuardHubConfig_Validate(t *testing.T) {
	cases := map[string]struct {
		mutate func(*WireGuardHubConfig)
		reason string
	}{
		"empty name":   {func(c *WireGuardHubConfig) { c.Name = "" }, "device name"},
		"no key ref":   {func(c *WireGuardHubConfig) { c.KeyRef = "" }, "key-ref"},
		"port zero":    {func(c *WireGuardHubConfig) { c.ListenPort = 0 }, "listen-port"},
		"port high":    {func(c *WireGuardHubConfig) { c.ListenPort = 70000 }, "listen-port"},
		"no addresses": {func(c *WireGuardHubConfig) { c.Addresses = nil }, "address"},
		"bad address":  {func(c *WireGuardHubConfig) { c.Addresses = []netip.Prefix{{}} }, "not valid"},
		"mtu":          {func(c *WireGuardHubConfig) { c.MTU = 9 }, "MTU"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := hubConfig()
			tc.mutate(&cfg)
			_, err := newWireGuardHubWithOps(nil, cfg, &mockKeys{}, newMockNetlinkOps(), &recordingWG{})
			var invalid *ErrInvalidTunnelConfig
			if !errors.As(err, &invalid) || !strings.Contains(invalid.Reason, tc.reason) {
				t.Fatalf("err = %v, want reason %q", err, tc.reason)
			}
		})
	}
	t.Run("no key provider", func(t *testing.T) {
		_, err := newWireGuardHubWithOps(nil, hubConfig(), nil, newMockNetlinkOps(), &recordingWG{})
		var need *ErrKeyProviderRequired
		if !errors.As(err, &need) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("custom mtu applied", func(t *testing.T) {
		cfg := hubConfig()
		cfg.MTU = 1380
		keys, _ := hubKeys(t, cfg)
		nl := newMockNetlinkOps()
		hub, err := newWireGuardHubWithOps(nil, cfg, keys, nl, &recordingWG{})
		if err != nil {
			t.Fatal(err)
		}
		if err := hub.Up(context.Background()); err != nil {
			t.Fatal(err)
		}
		if nl.links["wg-vpn0"].Attrs().MTU != 1380 {
			t.Fatalf("mtu = %d", nl.links["wg-vpn0"].Attrs().MTU)
		}
	})
}

func TestNewWireGuardHub_RefusesAnInvalidConfig(t *testing.T) {
	// The exported constructor validates before it opens any socket, so the
	// refusal path runs without CAP_NET_ADMIN.
	_, err := NewWireGuardHub(nil, WireGuardHubConfig{}, &mockKeys{})
	var invalid *ErrInvalidTunnelConfig
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want ErrInvalidTunnelConfig", err)
	}
}

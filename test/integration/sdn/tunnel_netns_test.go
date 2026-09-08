//go:build integration

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

package sdn

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

const (
	tunHostOuter = "10.97.0.1"
	tunPeerOuter = "10.97.0.2"
	tunHostInner = "10.255.9.1"
	tunPeerInner = "10.255.9.2"
	tunTable     = 141
	tunEchoPort  = 18179
	espSPIOut    = 0x5001
	espSPIIn     = 0x5002
)

// staticKeys is the test KeyProvider: fixed AES-256-GCM material for both
// SAs. In production the provider is the SDK KMS; here the point is that the
// manager programs the kernel with whatever the provider returns and the
// peer namespace is programmed with the same bytes by hand.
type staticKeys struct{ material map[string][]byte }

func (s staticKeys) Key(_ context.Context, ref string) ([]byte, error) {
	return append([]byte(nil), s.material[ref]...), nil
}

func espKeyBytes(b byte) []byte { return bytes.Repeat([]byte{b}, 36) }

// TestTunnel_NetNS_GREPinnedToUplink brings up a GRE tunnel between two
// namespaces with the host side managed by tunnel.Manager, pinned to an
// UplinkManager table, and proves traffic flows through the tunnel while the
// outer packets are routed by the uplink's table.
func TestTunnel_NetNS_GREPinnedToUplink(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "the tunnel test needs root (NET_ADMIN); run it in the devcontainer")
	hostNS, peerNS, hh, ph := twoNamespaces(t, "tun")
	defer hh.Close()
	defer ph.Close()

	// Peer side: a plain GRE tunnel by hand.
	require.NoError(t, ph.LinkAdd(&netlink.Gretun{LinkAttrs: netlink.LinkAttrs{Name: "pgre1"},
		Local: net.ParseIP(tunPeerOuter), Remote: net.ParseIP(tunHostOuter)}))
	addrUp(t, ph, "pgre1", tunPeerInner+"/30")
	listenWithin(peerNS, t, net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort)))

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var mgr *tunnel.Manager
	var uplinks *tunnel.UplinkManager
	inNS(t, hostNS, func() {
		uplinks = tunnel.NewUplinkManager(logger)
		require.NoError(t, uplinks.EnsureUplink(context.Background(), tunnel.UplinkConfig{
			Name: "isp-a", Interface: "tun0", Table: tunTable, GatewayV4: tunPeerOuter, Addresses: []string{tunHostOuter + "/24"},
		}))
		mgr = tunnel.NewManager(logger, tunnel.WithUplinks(uplinks))
		require.NoError(t, mgr.EnsureTunnel(context.Background(), tunnel.TunnelConfig{
			Name: "hgre1", Type: tunnel.TunnelTypeGRE, Uplink: "isp-a",
			Local: tunHostOuter, Remote: tunPeerOuter, TunnelIP: tunHostInner + "/30",
		}))
	})
	t.Cleanup(func() {
		inNS(t, hostNS, func() { _ = mgr.Close(); _ = uplinks.Close() })
	})

	// The tunnel carries traffic.
	require.NoError(t, dialWithin(hostNS, t, net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort))))

	// The uplink table holds the default and the pin rule exists.
	routes, err := hh.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: tunTable}, netlink.RT_FILTER_TABLE)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	assert.Equal(t, tunPeerOuter, routes[0].Gw.String())
	rules, err := hh.RuleList(netlink.FAMILY_V4)
	require.NoError(t, err)
	var pinned bool
	for _, r := range rules {
		if r.Table == tunTable && r.Dst != nil && r.Dst.IP.String() == tunPeerOuter {
			pinned = true
		}
	}
	assert.True(t, pinned, "the tunnel's outer endpoints are pinned to table %d", tunTable)

	// Status reflects the kernel.
	var st *tunnel.TunnelStatus
	inNS(t, hostNS, func() {
		st, err = mgr.Status(context.Background(), "hgre1")
	})
	require.NoError(t, err)
	assert.Equal(t, tunnel.TunnelStateUp, st.State)

	inNS(t, hostNS, func() { require.NoError(t, mgr.RemoveTunnel(context.Background(), "hgre1")) })
	rules, err = hh.RuleList(netlink.FAMILY_V4)
	require.NoError(t, err)
	for _, r := range rules {
		if r.Table == tunTable && r.Dst != nil {
			t.Fatalf("pin rule survived tunnel removal: %+v", r)
		}
	}
}

// TestTunnel_NetNS_IPsecProtectsTheCarrier wraps the GRE carrier in ESP on
// the managed side and programs the peer namespace's SAs and policies by
// hand with the same material, then proves traffic still flows — and that
// with mismatched keys it does not.
func TestTunnel_NetNS_IPsecProtectsTheCarrier(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "the tunnel test needs root (NET_ADMIN); run it in the devcontainer")
	hostNS, peerNS, hh, ph := twoNamespaces(t, "esp")
	defer hh.Close()
	defer ph.Close()

	keys := staticKeys{material: map[string][]byte{"k/out": espKeyBytes(0xA5), "k/in": espKeyBytes(0x5A)}}
	peerSAs := func(outKey, inKey []byte) {
		hostIP, peerIP := net.ParseIP(tunHostOuter), net.ParseIP(tunPeerOuter)
		// Peer's outbound mirrors the host's inbound and vice versa.
		for _, s := range []*netlink.XfrmState{
			{Src: peerIP, Dst: hostIP, Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT, Spi: espSPIIn, Reqid: espSPIOut, ReplayWindow: 128, ESN: true,
				Aead: &netlink.XfrmStateAlgo{Name: "rfc4106(gcm(aes))", Key: inKey, ICVLen: 128}},
			{Src: hostIP, Dst: peerIP, Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT, Spi: espSPIOut, Reqid: espSPIOut, ReplayWindow: 128, ESN: true,
				Aead: &netlink.XfrmStateAlgo{Name: "rfc4106(gcm(aes))", Key: outKey, ICVLen: 128}},
		} {
			require.NoError(t, ph.XfrmStateAdd(s))
		}
		host32 := &net.IPNet{IP: hostIP.To4(), Mask: net.CIDRMask(32, 32)}
		peer32 := &net.IPNet{IP: peerIP.To4(), Mask: net.CIDRMask(32, 32)}
		for _, p := range []*netlink.XfrmPolicy{
			{Src: peer32, Dst: host32, Proto: 47, Dir: netlink.XFRM_DIR_OUT, Action: netlink.XFRM_POLICY_ALLOW,
				Tmpls: []netlink.XfrmPolicyTmpl{{Src: peerIP, Dst: hostIP, Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT, Reqid: espSPIOut}}},
			{Src: host32, Dst: peer32, Proto: 47, Dir: netlink.XFRM_DIR_IN, Action: netlink.XFRM_POLICY_ALLOW,
				Tmpls: []netlink.XfrmPolicyTmpl{{Src: hostIP, Dst: peerIP, Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT, Reqid: espSPIOut}}},
		} {
			require.NoError(t, ph.XfrmPolicyAdd(p))
		}
	}

	require.NoError(t, ph.LinkAdd(&netlink.Gretun{LinkAttrs: netlink.LinkAttrs{Name: "pgre2"},
		Local: net.ParseIP(tunPeerOuter), Remote: net.ParseIP(tunHostOuter)}))
	addrUp(t, ph, "pgre2", tunPeerInner+"/30")
	listenWithin(peerNS, t, net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort)))

	// Peer programmed with the WRONG inbound key first: traffic must not flow.
	peerSAs(espKeyBytes(0xA5), espKeyBytes(0xFF))

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var mgr *tunnel.Manager
	cfg := tunnel.TunnelConfig{
		Name: "hgre2", Type: tunnel.TunnelTypeGRE, Transport: tunnel.TransportIPsec,
		Local: tunHostOuter, Remote: tunPeerOuter, TunnelIP: tunHostInner + "/30",
		IPsec: &tunnel.IPsecConfig{KeyRef: "k/out", PeerKeyRef: "k/in", SPIOut: espSPIOut, SPIIn: espSPIIn},
	}
	inNS(t, hostNS, func() {
		mgr = tunnel.NewManager(logger, tunnel.WithKeyProvider(keys))
		require.NoError(t, mgr.EnsureTunnel(context.Background(), cfg))
	})
	t.Cleanup(func() { inNS(t, hostNS, func() { _ = mgr.Close() }) })

	states, err := hh.XfrmStateList(netlink.FAMILY_V4)
	require.NoError(t, err)
	assert.Len(t, states, 2, "two SAs on the managed side")
	policies, err := hh.XfrmPolicyList(netlink.FAMILY_V4)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(policies), 2)

	assert.Error(t, dialWithin(hostNS, t, net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort))),
		"mismatched ESP keys must not carry traffic")

	// Re-program the peer with the right material: traffic flows.
	peerStates, err := ph.XfrmStateList(netlink.FAMILY_V4)
	require.NoError(t, err)
	for i := range peerStates {
		require.NoError(t, ph.XfrmStateDel(&peerStates[i]))
	}
	peerPolicies, err := ph.XfrmPolicyList(netlink.FAMILY_V4)
	require.NoError(t, err)
	for i := range peerPolicies {
		require.NoError(t, ph.XfrmPolicyDel(&peerPolicies[i]))
	}
	peerSAs(espKeyBytes(0xA5), espKeyBytes(0x5A))
	require.NoError(t, dialWithin(hostNS, t, net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort))),
		"matching ESP keys carry the GRE tunnel")

	// Rekey in lockstep: rotate both sides, traffic still flows.
	keys.material["k/out"] = espKeyBytes(0x11)
	keys.material["k/in"] = espKeyBytes(0x22)
	inNS(t, hostNS, func() { require.NoError(t, mgr.Rekey(context.Background(), "hgre2")) })
	peerStates, err = ph.XfrmStateList(netlink.FAMILY_V4)
	require.NoError(t, err)
	for i := range peerStates {
		s := peerStates[i]
		if s.Spi == espSPIIn {
			s.Aead.Key = espKeyBytes(0x22)
		} else {
			s.Aead.Key = espKeyBytes(0x11)
		}
		require.NoError(t, ph.XfrmStateUpdate(&s))
	}
	require.NoError(t, dialWithin(hostNS, t, net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort))),
		"traffic flows after a lockstep rekey")

	inNS(t, hostNS, func() { require.NoError(t, mgr.RemoveTunnel(context.Background(), "hgre2")) })
	states, err = hh.XfrmStateList(netlink.FAMILY_V4)
	require.NoError(t, err)
	assert.Empty(t, states, "SAs removed with the tunnel")
}

// twoNamespaces builds host and peer namespaces joined by a veth pair
// (tun0 in host, tun1 in peer) with the outer addresses on them.
func twoNamespaces(t *testing.T, tag string) (hostNS, peerNS netns.NsHandle, hh, ph *netlink.Handle) {
	t.Helper()
	hostNS = newNS(t)
	peerNS = newNS(t)
	var err error
	hh, err = netlink.NewHandleAt(hostNS)
	require.NoError(t, err)
	ph, err = netlink.NewHandleAt(peerNS)
	require.NoError(t, err)
	require.NoError(t, hh.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "tun0"}, PeerName: "tun1"}))
	peerLink, err := hh.LinkByName("tun1")
	require.NoError(t, err)
	require.NoError(t, hh.LinkSetNsFd(peerLink, int(peerNS)))
	for _, h := range []*netlink.Handle{hh, ph} {
		lo, err := h.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, h.LinkSetUp(lo))
	}
	addrUp(t, hh, "tun0", tunHostOuter+"/24")
	addrUp(t, ph, "tun1", tunPeerOuter+"/24")
	_ = tag
	return hostNS, peerNS, hh, ph
}

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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

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
	wgHostPort   = 51820
	wgPeerPort   = 51821

	// wgRekeyTimeout and wgRekeyJitterMax are WireGuard's REKEY_TIMEOUT and
	// its retransmit jitter (whitepaper §6.1, §6.4): a lost handshake
	// initiation is resent only after both.
	wgRekeyTimeout   = 5 * time.Second
	wgRekeyJitterMax = 333 * time.Millisecond
	// wgHandshakeWithin covers a lost first initiation and a lost first
	// retry, so a loaded runner does not fail a tunnel that is correct.
	wgHandshakeWithin = 2 * (wgRekeyTimeout + wgRekeyJitterMax)
	wgHandshakePoll   = 50 * time.Millisecond
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

// peerESP programs the peer's side of the host's ESP tunnel: the peer's
// outbound SA mirrors the host's inbound one and vice versa.
func peerESP(t *testing.T, ph *netlink.Handle, outKey, inKey []byte) {
	t.Helper()
	hostIP, peerIP := net.ParseIP(tunHostOuter), net.ParseIP(tunPeerOuter)
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
	require.NoError(t, ph.LinkAdd(&netlink.Gretun{LinkAttrs: netlink.LinkAttrs{Name: "pgre2"},
		Local: net.ParseIP(tunPeerOuter), Remote: net.ParseIP(tunHostOuter)}))
	addrUp(t, ph, "pgre2", tunPeerInner+"/30")
	listenWithin(peerNS, t, net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort)))

	// Peer programmed with the WRONG inbound key first: traffic must not flow.
	peerESP(t, ph, espKeyBytes(0xA5), espKeyBytes(0xFF))

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
	peerESP(t, ph, espKeyBytes(0xA5), espKeyBytes(0x5A))
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

// TestTunnel_NetNS_IPsecRelaunchKeepsLiveSAs relaunches an IPsec tunnel's
// manager over the kernel state its killed predecessor left (#557). The
// carrier and both SAs are adopted, not recreated: the outbound SA keeps its
// install time and packet counter, and traffic flows after the relaunch.
func TestTunnel_NetNS_IPsecRelaunchKeepsLiveSAs(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "the tunnel test needs root (NET_ADMIN); run it in the devcontainer")
	hostNS, peerNS, hh, ph := twoNamespaces(t, "espr")
	defer hh.Close()
	defer ph.Close()

	keys := staticKeys{material: map[string][]byte{"k/out": espKeyBytes(0xA5), "k/in": espKeyBytes(0x5A)}}
	peerESP(t, ph, espKeyBytes(0xA5), espKeyBytes(0x5A))
	require.NoError(t, ph.LinkAdd(&netlink.Gretun{LinkAttrs: netlink.LinkAttrs{Name: "pgre3"},
		Local: net.ParseIP(tunPeerOuter), Remote: net.ParseIP(tunHostOuter)}))
	addrUp(t, ph, "pgre3", tunPeerInner+"/30")
	echo := net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort))
	listenWithin(peerNS, t, echo)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := tunnel.TunnelConfig{
		Name: "hgre3", Type: tunnel.TunnelTypeGRE, Transport: tunnel.TransportIPsec,
		Local: tunHostOuter, Remote: tunPeerOuter, TunnelIP: tunHostInner + "/30",
		IPsec: &tunnel.IPsecConfig{KeyRef: "k/out", PeerKeyRef: "k/in", SPIOut: espSPIOut, SPIIn: espSPIIn},
	}
	// The first manager is never closed: its carrier, SAs and policies stay
	// in the kernel, as a SIGKILL leaves them.
	inNS(t, hostNS, func() {
		killed := tunnel.NewManager(logger, tunnel.WithKeyProvider(keys))
		require.NoError(t, killed.EnsureTunnel(context.Background(), cfg))
	})
	require.NoError(t, dialWithin(hostNS, t, echo), "the first manager's tunnel carries traffic")
	carrier, err := hh.LinkByName("hgre3")
	require.NoError(t, err)
	before := hostOutSA(t, hh)
	require.NotZero(t, before.Statistics.Packets, "precondition: the outbound SA has carried traffic")

	var relaunched *tunnel.Manager
	inNS(t, hostNS, func() {
		relaunched = tunnel.NewManager(logger, tunnel.WithKeyProvider(keys))
		require.NoError(t, relaunched.EnsureTunnel(context.Background(), cfg))
	})
	t.Cleanup(func() { inNS(t, hostNS, func() { _ = relaunched.Close() }) })

	adopted, err := hh.LinkByName("hgre3")
	require.NoError(t, err)
	assert.Equal(t, carrier.Attrs().Index, adopted.Attrs().Index, "the carrier is adopted")
	states, err := hh.XfrmStateList(netlink.FAMILY_V4)
	require.NoError(t, err)
	assert.Len(t, states, 2, "no SA is added beside the live ones")
	kept := hostOutSA(t, hh)
	assert.Equal(t, before.Statistics.AddTime, kept.Statistics.AddTime, "the outbound SA is the one installed before the relaunch")
	assert.GreaterOrEqual(t, kept.Statistics.Packets, before.Statistics.Packets, "its counters were not reset")
	require.NoError(t, dialWithin(hostNS, t, echo), "traffic flows after the relaunch")
}

// hostOutSA is the host's outbound SA as the kernel holds it.
func hostOutSA(t *testing.T, hh *netlink.Handle) *netlink.XfrmState {
	t.Helper()
	sa, err := hh.XfrmStateGet(&netlink.XfrmState{
		Src: net.ParseIP(tunHostOuter), Dst: net.ParseIP(tunPeerOuter),
		Proto: netlink.XFRM_PROTO_ESP, Spi: espSPIOut,
	})
	require.NoError(t, err)
	return sa
}

// twoNamespaces builds host and peer namespaces joined by a veth pair
// (tun0 in host, tun1 in peer) with the outer addresses on them.
// TestTunnel_NetNS_WireGuardRelaunchAdopts brings up a WireGuard tunnel
// between two namespaces, leaves its device behind as a killed process
// does, and proves a relaunched manager adopts it: the same interface, the
// same session, the stale peer gone, traffic still flowing. A changed key is
// not adopted: the device is recreated.
func TestTunnel_NetNS_WireGuardRelaunchAdopts(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "the tunnel test needs root (NET_ADMIN); run it in the devcontainer")
	hostNS, peerNS, hh, ph := twoNamespaces(t, "wg")
	defer hh.Close()
	defer ph.Close()

	hostKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	keys := staticKeys{material: map[string][]byte{"wg/host": hostKey[:]}}

	// Peer side: a WireGuard device by hand that knows the host's key.
	require.NoError(t, ph.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "pwg1"}}))
	peerConfigure(t, peerNS, "pwg1", peerKey, hostKey.PublicKey())
	addrUp(t, ph, "pwg1", tunPeerInner+"/30")
	listenWithin(peerNS, t, net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort)))

	cfg := tunnel.TunnelConfig{
		Name: "hwg1", Transport: tunnel.TransportWireGuard,
		Local: tunHostOuter, Remote: tunPeerOuter, TunnelIP: tunHostInner + "/30",
		WireGuard: &tunnel.WireGuardConfig{
			KeyRef: "wg/host", PeerPublicKey: peerKey.PublicKey().String(),
			ListenPort: wgHostPort, RemotePort: wgPeerPort,
		},
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ensure := func() *tunnel.Manager {
		var mgr *tunnel.Manager
		inNS(t, hostNS, func() {
			mgr = tunnel.NewManager(logger, tunnel.WithKeyProvider(keys))
			require.NoError(t, mgr.EnsureTunnel(context.Background(), cfg))
		})
		t.Cleanup(func() { inNS(t, hostNS, func() { _ = mgr.Close() }) })
		return mgr
	}

	// The first manager is never closed: its device stays, as a kill leaves it.
	ensure()
	awaitHandshake(t, hostNS, "hwg1", time.Time{})
	require.NoError(t, dialWithin(hostNS, t, net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort))))
	first, err := hh.LinkByName("hwg1")
	require.NoError(t, err)
	session := hostDevice(t, hostNS, "hwg1").Peers[0].LastHandshakeTime
	require.False(t, session.IsZero(), "precondition: the first manager completed a handshake")

	// A peer nobody configured, as a predecessor could have left it.
	stale, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	inNS(t, hostNS, func() {
		c, err := wgctrl.New()
		require.NoError(t, err)
		defer c.Close()
		_, staleNet, err := net.ParseCIDR("10.255.99.0/24")
		require.NoError(t, err)
		require.NoError(t, c.ConfigureDevice("hwg1", wgtypes.Config{Peers: []wgtypes.PeerConfig{{
			PublicKey: stale.PublicKey(), AllowedIPs: []net.IPNet{*staleNet},
		}}}))
	})

	t.Run("RelaunchAdoptsTheDevice", func(t *testing.T) {
		ensure()
		adopted, err := hh.LinkByName("hwg1")
		require.NoError(t, err)
		assert.Equal(t, first.Attrs().Index, adopted.Attrs().Index, "the relaunch kept the interface")
		device := hostDevice(t, hostNS, "hwg1")
		require.Len(t, device.Peers, 1, "the stale peer is removed by the diff")
		assert.Equal(t, peerKey.PublicKey(), device.Peers[0].PublicKey)
		assert.Equal(t, session, device.Peers[0].LastHandshakeTime, "the session survived the relaunch")
		require.NoError(t, dialWithin(hostNS, t, net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort))))
	})

	t.Run("ChangedKeyRecreatesTheDevice", func(t *testing.T) {
		rotated, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)
		keys.material["wg/host"] = rotated[:]

		// The peer learns the new key first, as the control plane delivers
		// it. The recreated device sends its first handshake initiation the
		// moment it comes up (persistent keepalive); a peer that still knew
		// only the old key would drop it, and WireGuard retries only after
		// REKEY_TIMEOUT (5s), longer than the dial waits. The product brings
		// the device up only once its key, peer and address are set, but the
		// initiation is one datagram a loaded runner can still lose, so the
		// dial waits for the new device's handshake.
		peerConfigure(t, peerNS, "pwg1", peerKey, rotated.PublicKey())
		ensure()
		recreated, err := hh.LinkByName("hwg1")
		require.NoError(t, err)
		assert.NotEqual(t, first.Attrs().Index, recreated.Attrs().Index, "a device with another key is not adopted")
		assert.Equal(t, rotated.PublicKey(), hostDevice(t, hostNS, "hwg1").PublicKey)
		awaitHandshake(t, hostNS, "hwg1", session)

		// Traffic flows over the new device.
		require.NoError(t, dialWithin(hostNS, t, net.JoinHostPort(tunPeerInner, strconv.Itoa(tunEchoPort))))
	})
}

// peerConfigure keys the peer namespace's WireGuard device and makes the
// host's public key its only peer.
func peerConfigure(t *testing.T, peerNS netns.NsHandle, name string, key wgtypes.Key, host wgtypes.Key) {
	t.Helper()
	_, hostNet, err := net.ParseCIDR(tunHostInner + "/32")
	require.NoError(t, err)
	listen := wgPeerPort
	inNS(t, peerNS, func() {
		c, err := wgctrl.New()
		require.NoError(t, err)
		defer c.Close()
		require.NoError(t, c.ConfigureDevice(name, wgtypes.Config{
			PrivateKey: &key, ListenPort: &listen, ReplacePeers: true,
			Peers: []wgtypes.PeerConfig{{
				PublicKey: host, AllowedIPs: []net.IPNet{*hostNet},
				Endpoint: &net.UDPAddr{IP: net.ParseIP(tunHostOuter), Port: wgHostPort},
			}},
		}))
	})
}

// hostDevice reads a WireGuard device back from the host namespace.
func hostDevice(t *testing.T, hostNS netns.NsHandle, name string) *wgtypes.Device {
	t.Helper()
	var device *wgtypes.Device
	inNS(t, hostNS, func() {
		c, err := wgctrl.New()
		require.NoError(t, err)
		defer c.Close()
		device, err = c.Device(name)
		require.NoError(t, err)
	})
	return device
}

// awaitHandshake waits until the host device's only peer has completed a
// handshake later than since, and returns that handshake's time. The first
// initiation of a new device is one UDP datagram; when it is lost WireGuard
// resends it only after REKEY_TIMEOUT, longer than a single dial waits.
func awaitHandshake(t *testing.T, hostNS netns.NsHandle, name string, since time.Time) time.Time {
	t.Helper()
	deadline := time.NewTimer(wgHandshakeWithin)
	defer deadline.Stop()
	poll := time.NewTicker(wgHandshakePoll)
	defer poll.Stop()
	for {
		device := hostDevice(t, hostNS, name)
		require.Len(t, device.Peers, 1)
		if last := device.Peers[0].LastHandshakeTime; last.After(since) {
			return last
		}
		select {
		case <-deadline.C:
			require.FailNowf(t, "no handshake", "%s completed no handshake after %s within %s", name, since, wgHandshakeWithin)
		case <-poll.C:
		}
	}
}

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

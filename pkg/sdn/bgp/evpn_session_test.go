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

package bgp

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EVPN between real, in-process GoBGP speakers: two VTEPs, each an iBGP
// l2vpn-evpn route-reflector client of a third speaker, the RR a control
// plane node runs. Each VTEP runs an EVPNManager on its speaker.

// The fabric: the RR and the VTEPs' BGP sessions on loopback, and the
// VTEPs' tunnel addresses.
var (
	rrSession    = netip.MustParseAddr("127.0.0.1")
	vtepASession = netip.MustParseAddr("127.0.0.2")
	vtepBSession = netip.MustParseAddr("127.0.0.3")

	vtepAMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x00, 0x00, 0x0a}
	vtepBMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x00, 0x00, 0x0b}
)

const (
	sessionL2VNI uint32 = 10100
	// sessionL3VNI needs all 24 label bits: a label shifted left by four,
	// as VXLAN over MPLS-style encodings do, would not survive the session.
	sessionL3VNI uint32 = 0xfedcba
)

// fabricPolicy admits the overlay route targets of the test VNIs, both ways.
func fabricPolicy(t *testing.T) PeerPolicyConfig {
	rts := []string{mustRT(t, sessionL2VNI).String(), mustRT(t, sessionL3VNI).String()}
	return PeerPolicyConfig{ImportRouteTargets: rts, ExportRouteTargets: rts}
}

// startFabricSpeaker starts a speaker and stops it at the end of the test.
func startFabricSpeaker(t *testing.T, config *BGPConfig, opts ...SpeakerOption) *Speaker {
	t.Helper()
	s, err := NewSpeaker(config, speakerTestLogger(), opts...)
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() { assert.NoError(t, s.Stop(context.Background())) })
	return s
}

// evpnFabric starts the RR and both VTEP speakers and waits until the RR
// has both sessions. The VTEPs listen passively on one port at their own
// loopback addresses; the RR dials them.
func evpnFabric(t *testing.T) (rr, a, b *Speaker) {
	t.Helper()
	ctx := context.Background()
	vtepPort := freePort(t)
	policy := fabricPolicy(t)

	vtep := func(routerID string, session netip.Addr) *Speaker {
		s := startFabricSpeaker(t, &BGPConfig{
			RouterID:        netip.MustParseAddr(routerID),
			ASN:             64512,
			ListenAddresses: []netip.Addr{session},
			ListenPort:      vtepPort,
			EnabledFamilies: []AddressFamily{AFamilyEVPN},
		})
		require.NoError(t, s.AddPeer(ctx, &NeighborConfig{
			Name:            "route-reflector",
			Address:         rrSession,
			ASN:             64512,
			PassiveMode:     true,
			EnabledFamilies: []AddressFamily{AFamilyEVPN},
			Policy:          policy,
		}))
		return s
	}
	a = vtep("192.0.2.11", vtepASession)
	b = vtep("192.0.2.12", vtepBSession)

	rr = startFabricSpeaker(t, &BGPConfig{
		RouterID:         netip.MustParseAddr("192.0.2.1"),
		ASN:              64512,
		ListenAddresses:  []netip.Addr{rrSession},
		ListenPort:       freePort(t),
		EnabledFamilies:  []AddressFamily{AFamilyEVPN},
		IsRouteReflector: true,
		ClusterID:        "10.255.0.1",
	}, WithBGPServer(remotePortServer{
		BGPServerInterface: NewGoBGPServerAdapter(server.NewBgpServer()),
		port:               uint32(vtepPort),
	}))
	for name, session := range map[string]netip.Addr{"vtep-a": vtepASession, "vtep-b": vtepBSession} {
		require.NoError(t, rr.AddPeer(ctx, &NeighborConfig{
			Name:                 name,
			Address:              session,
			ASN:                  64512,
			RouteReflectorClient: true,
			EnabledFamilies:      []AddressFamily{AFamilyEVPN},
			Policy:               policy,
		}))
	}
	for _, session := range []netip.Addr{vtepASession, vtepBSession} {
		requireEstablished(t, rr, session)
	}
	return rr, a, b
}

// requireEstablished waits until s has an established session with peer.
func requireEstablished(t *testing.T, s *Speaker, peer netip.Addr) {
	t.Helper()
	require.Eventually(t, func() bool {
		state, err := s.GetPeerState(context.Background(), peer)
		return err == nil && state == PeerStateEstablished
	}, sessionWait, 20*time.Millisecond, "the session with %s never established", peer)
}

// TestEVPNSession_OutboundOnlyBesideTransitListener is gatewayd with both a
// transit `bgp:` section and overlay RR peers: the transit speaker holds the
// BGP port on the VTEP's address, and the overlay speaker still starts and
// reaches its route reflector, because it only dials. A second listener on
// that address and port fails to start, which is how the combination broke.
func TestEVPNSession_OutboundOnlyBesideTransitListener(t *testing.T) {
	ctx := context.Background()
	bgpPort := freePort(t)
	rrPort := freePort(t)

	startFabricSpeaker(t, &BGPConfig{
		RouterID:        netip.MustParseAddr("192.0.2.20"),
		ASN:             64600,
		ListenAddresses: []netip.Addr{vtepASession},
		ListenPort:      bgpPort,
	})

	rr := startFabricSpeaker(t, &BGPConfig{
		RouterID:         netip.MustParseAddr("192.0.2.1"),
		ASN:              64512,
		ListenAddresses:  []netip.Addr{rrSession},
		ListenPort:       rrPort,
		EnabledFamilies:  []AddressFamily{AFamilyEVPN},
		IsRouteReflector: true,
		ClusterID:        "10.255.0.1",
	})
	require.NoError(t, rr.AddPeer(ctx, &NeighborConfig{
		Name:                 "overlay-vtep",
		Address:              vtepASession,
		ASN:                  64512,
		PassiveMode:          true,
		RouteReflectorClient: true,
		EnabledFamilies:      []AddressFamily{AFamilyEVPN},
		Policy:               fabricPolicy(t),
	}))

	overlayConfig := func(outboundOnly bool) *BGPConfig {
		return &BGPConfig{
			RouterID:        netip.MustParseAddr("192.0.2.11"),
			ASN:             64512,
			ListenAddresses: []netip.Addr{vtepASession},
			ListenPort:      bgpPort,
			OutboundOnly:    outboundOnly,
			SessionSource:   vtepASession,
			EnabledFamilies: []AddressFamily{AFamilyEVPN},
		}
	}
	dialRR := WithBGPServer(remotePortServer{
		BGPServerInterface: NewGoBGPServerAdapter(server.NewBgpServer()),
		port:               uint32(rrPort),
	})

	listening, err := NewSpeaker(overlayConfig(false), speakerTestLogger(), dialRR)
	require.NoError(t, err)
	require.Error(t, listening.Start(ctx), "a second listener on the transit speaker's address and port must not start")

	overlay := startFabricSpeaker(t, overlayConfig(true), WithBGPServer(remotePortServer{
		BGPServerInterface: NewGoBGPServerAdapter(server.NewBgpServer()),
		port:               uint32(rrPort),
	}))
	require.NoError(t, overlay.AddPeer(ctx, &NeighborConfig{
		Name:            "route-reflector",
		Address:         rrSession,
		ASN:             64512,
		EnabledFamilies: []AddressFamily{AFamilyEVPN},
		Policy:          fabricPolicy(t),
	}))

	requireEstablished(t, overlay, rrSession)
	requireEstablished(t, rr, vtepASession)
}

// startVTEPManager runs an EVPN manager on a VTEP speaker, joined to the
// test L2VNI with the test L3VNI, and records what it imports.
func startVTEPManager(t *testing.T, s *Speaker, vtepIP netip.Addr, routerMAC net.HardwareAddr) (*EVPNManager, *notifications) {
	t.Helper()
	ctx := context.Background()
	m, err := NewEVPNManager(&EVPNManagerConfig{
		Speaker:    s,
		Logger:     testLogger(),
		LocalVTEP:  vtepIP,
		OverlayASN: 65000,
		RouterMAC:  routerMAC,
	})
	require.NoError(t, err)
	imported := &notifications{}
	m.RegisterHandler(imported.handle)
	require.NoError(t, m.Start(ctx))
	t.Cleanup(func() { assert.NoError(t, m.Stop(context.Background())) })
	require.NoError(t, m.JoinVNI(ctx, sessionL2VNI, sessionL3VNI))
	return m, imported
}

// waitForImport waits until a handler was told of a route matching match
// and returns the latest such route.
func waitForImport(t *testing.T, n *notifications, what string, match func(*EVPNRouteData) bool) *EVPNRouteData {
	t.Helper()
	var found *EVPNRouteData
	require.Eventually(t, func() bool {
		n.mu.Lock()
		defer n.mu.Unlock()
		for i := len(n.routes) - 1; i >= 0; i-- {
			if match(n.routes[i]) {
				found = n.routes[i]
				return true
			}
		}
		return false
	}, sessionWait, 20*time.Millisecond, "never imported %s", what)
	return found
}

// remoteMACAt waits until m reaches mac at vtep.
func remoteMACAt(t *testing.T, m *EVPNManager, mac net.HardwareAddr, vtep netip.Addr) {
	t.Helper()
	require.Eventually(t, func() bool {
		at, ok := m.RemoteMAC(sessionL2VNI, mac)
		return ok && at == vtep
	}, sessionWait, 20*time.Millisecond, "%s never reached at %s", mac, vtep)
}

// TestEVPNSession_RouteReflector is the overlay control plane end to end:
// Type-3, Type-2 and Type-5 routes cross the RR with their RDs, route
// targets, raw VNI labels and router MAC intact, a MAC moves between the
// VTEPs by MAC Mobility sequence numbers, and the RR carries more EVPN
// routes than the unicast prefix limit.
func TestEVPNSession_RouteReflector(t *testing.T) {
	ctx := context.Background()
	rr, speakerA, speakerB := evpnFabric(t)
	managerA, importedA := startVTEPManager(t, speakerA, vtepA, vtepAMAC)
	managerB, importedB := startVTEPManager(t, speakerB, vtepB, vtepBMAC)

	rdA, ok := managerA.RouteDistinguisher(sessionL2VNI)
	require.True(t, ok)

	t.Run("Type-3: each VTEP learns the other's flood list entry", func(t *testing.T) {
		require.Eventually(t, func() bool {
			return slices.Equal(managerB.RemoteVTEPs(sessionL2VNI), []netip.Addr{vtepA}) &&
				slices.Equal(managerA.RemoteVTEPs(sessionL2VNI), []netip.Addr{vtepB})
		}, sessionWait, 20*time.Millisecond)

		imet := waitForImport(t, importedB, "A's Type-3 route", func(r *EVPNRouteData) bool {
			return r.Type == EVPNTypeInclusiveMulticast && r.IMET.VTEPIP == vtepA
		})
		assert.Equal(t, rdA, imet.RD)
		assert.Equal(t, "192.0.2.11:1", imet.RD.String())
		assert.Equal(t, []RouteTarget{mustRT(t, sessionL2VNI)}, imet.RouteTargets)
		assert.Equal(t, sessionL2VNI, imet.IMET.VNI, "the PMSI label is the raw VNI")
	})

	hostMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0x00, 0x01}
	hostIP := netip.MustParseAddr("10.1.0.10")

	t.Run("Type-2: symmetric IRB with both VNIs and the router MAC", func(t *testing.T) {
		require.NoError(t, managerA.AdvertiseMACIP(ctx, &MACIPEntry{MAC: hostMAC, IP: hostIP, VNI: sessionL2VNI}))
		remoteMACAt(t, managerB, hostMAC, vtepA)

		route := waitForImport(t, importedB, "A's MAC/IP route", func(r *EVPNRouteData) bool {
			return r.Type == EVPNTypeMACIPAdvertisement && r.MACIP.IP == hostIP && !r.IsWithdraw
		})
		assert.Equal(t, rdA, route.RD)
		assert.ElementsMatch(t, []RouteTarget{mustRT(t, sessionL2VNI), mustRT(t, sessionL3VNI)}, route.RouteTargets)
		assert.Equal(t, sessionL2VNI, route.MACIP.VNI)
		assert.Equal(t, sessionL3VNI, route.MACIP.L3VNI)
		assert.Equal(t, vtepAMAC, route.RouterMAC)
		assert.Equal(t, vtepA, route.NextHop)
		assert.Zero(t, route.MACIP.Sequence)

		mac, ok := managerB.LookupMACForIP(sessionL2VNI, hostIP)
		assert.True(t, ok)
		assert.Equal(t, hostMAC, mac)
	})

	t.Run("Type-5: an IP-VRF prefix with its own RD", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.1.0.0/24")
		require.NoError(t, managerA.AdvertisePrefix(ctx, sessionL3VNI, prefix))
		route := waitForImport(t, importedB, "A's Type-5 route", func(r *EVPNRouteData) bool {
			return r.Type == EVPNTypeIPPrefix && r.PrefixData.Prefix == prefix
		})
		assert.Equal(t, "192.0.2.11:2", route.RD.String())
		assert.Equal(t, []RouteTarget{mustRT(t, sessionL3VNI)}, route.RouteTargets)
		assert.Equal(t, sessionL3VNI, route.PrefixData.VNI)
		assert.Equal(t, vtepAMAC, route.RouterMAC)
	})

	t.Run("MAC Mobility: the MAC moves to B and back", func(t *testing.T) {
		require.NoError(t, managerB.AdvertiseMACIP(ctx, &MACIPEntry{MAC: hostMAC, IP: hostIP, VNI: sessionL2VNI}))
		remoteMACAt(t, managerA, hostMAC, vtepB)
		moved := waitForImport(t, importedA, "B's MAC/IP route", func(r *EVPNRouteData) bool {
			return r.Type == EVPNTypeMACIPAdvertisement && r.MACIP.VTEPIP == vtepB && r.MACIP.IP == hostIP
		})
		assert.Equal(t, uint32(1), moved.MACIP.Sequence, "A's sequence plus one")
		assert.Equal(t, vtepBMAC, moved.RouterMAC)
		var notFound ErrMACIPNotFound
		assert.ErrorAs(t, managerA.WithdrawMACIP(ctx, sessionL2VNI, hostMAC, hostIP), &notFound, "A gave the MAC up")

		require.NoError(t, managerA.AdvertiseMACIP(ctx, &MACIPEntry{MAC: hostMAC, IP: hostIP, VNI: sessionL2VNI}))
		remoteMACAt(t, managerB, hostMAC, vtepA)
		back := waitForImport(t, importedB, "A's route after the move back", func(r *EVPNRouteData) bool {
			return r.Type == EVPNTypeMACIPAdvertisement && r.MACIP.VTEPIP == vtepA && r.MACIP.Sequence == 2
		})
		assert.Equal(t, hostIP, back.MACIP.IP)
		assert.ErrorAs(t, managerB.WithdrawMACIP(ctx, sessionL2VNI, hostMAC, hostIP), &notFound, "B gave the MAC back")
	})

	t.Run("more EVPN routes than the unicast limit cross the RR", func(t *testing.T) {
		const macs = 1200
		require.Greater(t, uint32(macs), DefaultMaxPrefixes)
		mac := func(i int) net.HardwareAddr { return net.HardwareAddr{0x02, 0x10, 0, 0, byte(i >> 8), byte(i)} }
		for i := range macs {
			require.NoError(t, managerA.AdvertiseMACIP(ctx, &MACIPEntry{MAC: mac(i), VNI: sessionL2VNI}))
		}
		require.Eventually(t, func() bool {
			for i := range macs {
				if at, ok := managerB.RemoteMAC(sessionL2VNI, mac(i)); !ok || at != vtepA {
					return false
				}
			}
			return true
		}, sessionWait, 50*time.Millisecond, "B must reach all %d MACs at A", macs)
		for _, session := range []netip.Addr{vtepASession, vtepBSession} {
			state, err := rr.GetPeerState(ctx, session)
			require.NoError(t, err)
			assert.Equal(t, PeerStateEstablished, state, "the RR session with %s survives", session)
		}
	})
}

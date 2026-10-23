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
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/require"
)

// Overlay control-plane capability checks against real GoBGP (spike #716).
//
// The overlay design (release plan §5.2) puts every VTEP on an iBGP
// l2vpn-evpn session to route reflectors that accept "dynamic neighbours
// restricted to the fabric" and use RT-Constrain (RFC 4684) so a VTEP only
// receives the EVPN routes of the VNIs placed on it. These tests run real,
// started GoBGP speakers over loopback (no mocks) and prove both properties
// on the GoBGP version in go.mod, so a GoBGP bump that loses either fails
// here instead of in the fabric.
//
// Each speaker binds its own 127.0.0.x source address. Linux routes all of
// 127.0.0.0/8 to lo, so these are distinct, bindable sources without any
// host configuration. Listening ports are ephemeral, never 179.

const (
	overlayASN    = 65000
	rrAddress     = "127.0.0.1"
	fabricPrefix  = "127.0.0.0/29" // .1-.7: the "fabric"
	outsideSource = "127.0.0.9"    // a host outside the fabric prefix
	waitDeadline  = 30 * time.Second
)

// freeLoopbackPort reserves an ephemeral TCP port on the RR address and
// releases it for GoBGP to bind.
func freeLoopbackPort(t *testing.T) int32 {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(rrAddress, "0"))
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return int32(port)
}

// evpnAndRTC are the families every overlay session negotiates.
func evpnAndRTC() []*api.AfiSafi {
	family := func(afi api.Family_Afi, safi api.Family_Safi) *api.AfiSafi {
		return &api.AfiSafi{Config: &api.AfiSafiConfig{Family: &api.Family{Afi: afi, Safi: safi}, Enabled: true}}
	}
	return []*api.AfiSafi{
		family(api.Family_AFI_L2VPN, api.Family_SAFI_EVPN),
		family(api.Family_AFI_IP, api.Family_SAFI_ROUTE_TARGET_CONSTRAINTS),
	}
}

// startSpeaker starts a GoBGP speaker. listenPort -1 means it never listens
// (a VTEP only dials its route reflectors).
//
// Start every speaker of a test before any of them has a session. GoBGP keeps
// its route-selection options in package variables (table.SelectionOptions,
// table.UseMultiplePaths) that StartBgp writes (server.go:2697-2698) and every
// server's FSM reads (table_manager.go:379), so starting a speaker while
// another already has a session up is a data race between the two servers.
// The CI race job caught exactly that. Starting them all first orders the
// writes before any FSM goroutine exists.
func startSpeaker(t *testing.T, routerID string, listenPort int32) *server.BgpServer {
	t.Helper()
	s := server.NewBgpServer()
	go s.Serve()
	global := &api.Global{Asn: overlayASN, RouterId: routerID, ListenPort: listenPort}
	if listenPort > 0 {
		global.ListenAddresses = []string{rrAddress}
	}
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{Global: global}))
	return s
}

// stopFabric stops the route reflector, then each VTEP, when the test ends.
//
// The order closes a data race inside GoBGP v4.9.0, which runs each peer's
// FSM handler on its own goroutine: one peer's PeerDown propagates its
// withdrawals to every other neighbour, reading their config without a lock
// (propagateUpdateToNeighbors, server.go:1474), while a neighbour going down
// at the same instant writes its own (handleFSMMessage, server.go:1687).
// VTEPs stopped first drop their sessions together and the RR runs those
// PeerDowns at once. StopBgp on the RR instead deletes its neighbours one by
// one inside a single management operation that holds the server lock every
// FSM handler waits on, and returns only after the handlers exit; the VTEPs
// then stop with nothing left on the RR to race.
func stopFabric(t *testing.T, rr *server.BgpServer, vteps ...*server.BgpServer) {
	t.Helper()
	t.Cleanup(func() {
		for _, s := range append([]*server.BgpServer{rr}, vteps...) {
			require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
			s.Stop()
		}
	})
}

// startRouteReflector starts an RR that has no configured neighbours at
// all: VTEP sessions are admitted only through a dynamic-neighbour prefix
// bound to a peer group whose members are RR clients carrying l2vpn-evpn
// and RTC.
func startRouteReflector(t *testing.T) (*server.BgpServer, int32) {
	t.Helper()
	port := freeLoopbackPort(t)
	rr := startSpeaker(t, "10.255.0.1", port)
	ctx := context.Background()
	require.NoError(t, rr.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf:           &api.PeerGroupConf{PeerGroupName: "fabric", PeerAsn: overlayASN},
		RouteReflector: &api.RouteReflector{RouteReflectorClient: true, RouteReflectorClusterId: "10.255.0.1"},
		AfiSafis:       evpnAndRTC(),
	}}))
	require.NoError(t, rr.AddDynamicNeighbor(ctx, &api.AddDynamicNeighborRequest{
		DynamicNeighbor: &api.DynamicNeighbor{Prefix: fabricPrefix, PeerGroup: "fabric"},
	}))
	return rr, port
}

// peerEvents streams a speaker's peer state changes.
func peerEvents(t *testing.T, s *server.BgpServer) <-chan gobgp.FSMState {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := make(chan gobgp.FSMState, 64)
	require.NoError(t, s.WatchEvent(ctx, server.WatchEventMessageCallbacks{
		OnPeerUpdate: func(ev *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
			if ev.Type == apiutil.PEER_EVENT_STATE {
				ch <- ev.Peer.State.SessionState
			}
		},
	}, server.WatchPeer()))
	return ch
}

// startVTEP starts a VTEP speaker. It peers with nothing until connectVTEP.
func startVTEP(t *testing.T, routerID string) *server.BgpServer {
	t.Helper()
	return startSpeaker(t, routerID, -1)
}

// connectVTEP has a started VTEP dial the RR from source and waits until the
// session is established.
//
// Originate the routes a session must carry before connecting it. GoBGP
// publishes the ESTABLISHED peer event from inside its FSM callback, before it
// marks the peer established for advertising (fsmHandler.loop runs the
// callback, then fsm.state.Store). A path added in that window fails
// needToAdvertise and is never sent, because the callback's initial dump has
// already run. Routes in the RIB before the dial ride that dump. A route added
// after the session has delivered an UPDATE is safe, because GoBGP reads
// UPDATEs only once the peer is marked established.
func connectVTEP(t *testing.T, v *server.BgpServer, source string, rrPort int32) {
	t.Helper()
	events := peerEvents(t, v)
	require.NoError(t, v.AddPeer(context.Background(), &api.AddPeerRequest{Peer: vtepToRR(source, rrPort)}))
	waitForState(t, events, gobgp.BGP_FSM_ESTABLISHED)
}

func vtepToRR(source string, rrPort int32) *api.Peer {
	return &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: rrAddress, PeerAsn: overlayASN},
		Transport: &api.Transport{LocalAddress: source, RemotePort: uint32(rrPort)},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
		AfiSafis:  evpnAndRTC(),
	}
}

func waitForState(t *testing.T, events <-chan gobgp.FSMState, want gobgp.FSMState) {
	t.Helper()
	deadline := time.NewTimer(waitDeadline)
	defer deadline.Stop()
	for {
		select {
		case got := <-events:
			if got == want {
				return
			}
		case <-deadline.C:
			t.Fatalf("session never reached %s", want)
		}
	}
}

// routeTarget is a 2-octet-AS route target (overlayASN:vni).
func routeTarget(vni uint32) gobgp.ExtendedCommunityInterface {
	return gobgp.NewTwoOctetAsSpecificExtended(gobgp.EC_SUBTYPE_ROUTE_TARGET, overlayASN, vni, true)
}

// originateIMET originates an EVPN Type-3 (inclusive multicast) route for
// the given VNI, tagged with that VNI's route target. The VNI is also the
// Ethernet tag so the receiver can tell routes apart.
func originateIMET(t *testing.T, s *server.BgpServer, vtep string, vni uint32) {
	t.Helper()
	originateTagged(t, s, vtep, vni, vni)
}

// originateTagged originates a Type-3 route with Ethernet tag etag carrying
// the route target of vni.
func originateTagged(t *testing.T, s *server.BgpServer, vtep string, etag, vni uint32) {
	t.Helper()
	addr := netip.MustParseAddr(vtep)
	rd, err := gobgp.NewRouteDistinguisherIPAddressAS(addr, uint16(etag))
	require.NoError(t, err)
	nlri, err := gobgp.NewEVPNMulticastEthernetTagRoute(rd, etag, addr)
	require.NoError(t, err)
	nh, err := gobgp.NewPathAttributeNextHop(addr)
	require.NoError(t, err)
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Family: gobgp.RF_EVPN,
		Nlri:   nlri,
		Attrs: []gobgp.PathAttributeInterface{
			gobgp.NewPathAttributeOrigin(gobgp.BGP_ORIGIN_ATTR_TYPE_IGP),
			nh,
			gobgp.NewPathAttributeExtendedCommunities([]gobgp.ExtendedCommunityInterface{routeTarget(vni)}),
		},
	}}})
	require.NoError(t, err)
}

// joinVNI advertises RTC membership for a VNI's route target, the way a
// VTEP signals "send me this VNI's routes".
func joinVNI(t *testing.T, s *server.BgpServer, vtep string, vni uint32) {
	t.Helper()
	nh, err := gobgp.NewPathAttributeNextHop(netip.MustParseAddr(vtep))
	require.NoError(t, err)
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Family: gobgp.RF_RTC_UC,
		Nlri:   gobgp.NewRouteTargetMembershipNLRI(overlayASN, routeTarget(vni)),
		Attrs: []gobgp.PathAttributeInterface{
			gobgp.NewPathAttributeOrigin(gobgp.BGP_ORIGIN_ATTR_TYPE_IGP),
			nh,
		},
	}}})
	require.NoError(t, err)
}

// receivedVNIs streams the Ethernet tag (= VNI) of every EVPN Type-3 best
// path a speaker learns.
func receivedVNIs(t *testing.T, s *server.BgpServer) <-chan uint32 {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := make(chan uint32, 64)
	require.NoError(t, s.WatchEvent(ctx, server.WatchEventMessageCallbacks{
		OnBestPath: func(paths []*apiutil.Path, _ time.Time) {
			for _, p := range paths {
				evpn, ok := p.Nlri.(*gobgp.EVPNNLRI)
				if !ok || p.Withdrawal {
					continue
				}
				if imet, ok := evpn.RouteTypeData.(*gobgp.EVPNMulticastEthernetTagRoute); ok {
					ch <- imet.ETag
				}
			}
		},
	}, server.WatchBestPath(true)))
	return ch
}

// awaitVNI waits until want arrives and fails if forbidden arrives first.
func awaitVNI(t *testing.T, vnis <-chan uint32, want uint32, forbidden ...uint32) {
	t.Helper()
	deadline := time.NewTimer(waitDeadline)
	defer deadline.Stop()
	for {
		select {
		case got := <-vnis:
			for _, f := range forbidden {
				require.NotEqualf(t, f, got, "received VNI %d, whose route target this VTEP never joined", got)
			}
			if got == want {
				return
			}
		case <-deadline.C:
			t.Fatalf("VNI %d never arrived", want)
		}
	}
}

// TestRealGoBGP_RTConstrainFiltersEVPN proves RT-Constrain filters
// l2vpn-evpn routes on the RR's way out to a client, per client:
//
//   - VTEP A originates Type-3 routes for VNIs 100 and 200;
//   - VTEP B joins only VNI 100, VTEP C only VNI 200;
//   - C receiving VNI 200 proves the RR holds that route;
//   - A then originates one more route on RT 100 (Ethernet tag 100100) as
//     an ordering barrier: the RR sends to B in order over one session, so
//     B receiving it without ever having seen VNI 200 proves the RR filtered
//     VNI 200 toward B;
//   - B then joins VNI 200 and receives it (RFC 4684 §6 re-evaluation).
func TestRealGoBGP_RTConstrainFiltersEVPN(t *testing.T) {
	rr, rrPort := startRouteReflector(t)
	a := startVTEP(t, "10.0.0.2")
	b := startVTEP(t, "10.0.0.3")
	c := startVTEP(t, "10.0.0.4")
	stopFabric(t, rr, a, b, c)

	bVNIs := receivedVNIs(t, b)
	cVNIs := receivedVNIs(t, c)

	joinVNI(t, b, "127.0.0.3", 100)
	joinVNI(t, c, "127.0.0.4", 200)
	originateIMET(t, a, "127.0.0.2", 100)
	originateIMET(t, a, "127.0.0.2", 200)

	connectVTEP(t, a, "127.0.0.2", rrPort)
	connectVTEP(t, b, "127.0.0.3", rrPort)
	connectVTEP(t, c, "127.0.0.4", rrPort)

	awaitVNI(t, cVNIs, 200, 100)
	awaitVNI(t, bVNIs, 100, 200)

	// The barrier: a newer route on RT 100, sent after VNI 200 reached the
	// RR. Everything the RR would send B arrives before it.
	originateTagged(t, a, "127.0.0.2", 100100, 100)
	awaitVNI(t, bVNIs, 100100, 200)

	// Joining the route target delivers the route the RR withheld.
	joinVNI(t, b, "127.0.0.3", 200)
	awaitVNI(t, bVNIs, 200)
}

// probeRR opens a raw TCP connection to the RR from source and returns
// what the RR sends first. GoBGP answers an admitted connection with its
// OPEN at once; a connection from an address no neighbour or dynamic
// prefix matches is accepted and closed before a byte is written.
func probeRR(t *testing.T, source string, rrPort int32) ([]byte, error) {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}, Timeout: waitDeadline}
	conn, err := d.Dial("tcp", net.JoinHostPort(rrAddress, strconv.Itoa(int(rrPort))))
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close()) }()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(waitDeadline)))
	header := make([]byte, gobgp.BGP_HEADER_LENGTH)
	_, err = io.ReadFull(conn, header)
	return header, err
}

// TestRealGoBGP_DynamicNeighborsAdmitOnlyTheFabric proves an RR with no
// configured neighbours admits an l2vpn-evpn session from inside the
// dynamic-neighbour prefix (and learns its EVPN routes over it), and
// refuses a connection from outside the prefix.
func TestRealGoBGP_DynamicNeighborsAdmitOnlyTheFabric(t *testing.T) {
	rr, rrPort := startRouteReflector(t)
	inside := startVTEP(t, "10.0.0.2")
	stopFabric(t, rr, inside)
	rrVNIs := receivedVNIs(t, rr)

	joinVNI(t, inside, "127.0.0.2", 300)
	originateIMET(t, inside, "127.0.0.2", 300)
	connectVTEP(t, inside, "127.0.0.2", rrPort)
	awaitVNI(t, rrVNIs, 300)

	// A dynamic peer carries its address in State only: GoBGP's
	// newDynamicPeer never fills Conf.NeighborAddress.
	var dynamic []string
	require.NoError(t, rr.ListPeer(context.Background(), &api.ListPeerRequest{}, func(p *api.Peer) {
		dynamic = append(dynamic, p.State.NeighborAddress+"/"+p.Conf.PeerGroup+"/"+p.State.SessionState.String())
	}))
	require.Equal(t, []string{"127.0.0.2/fabric/SESSION_STATE_ESTABLISHED"}, dynamic,
		"the inside VTEP must be a dynamic member of the fabric peer group")

	t.Run("another fabric address is answered with an OPEN", func(t *testing.T) {
		header, err := probeRR(t, "127.0.0.5", rrPort)
		require.NoError(t, err)
		require.Equal(t, uint8(gobgp.BGP_MSG_OPEN), header[18], "the RR must open a session with a fabric address")
	})

	t.Run("an address outside the prefix is closed unanswered", func(t *testing.T) {
		header, err := probeRR(t, outsideSource, rrPort)
		require.ErrorIs(t, err, io.EOF, "the RR must close a connection from outside %s without a byte (got % x)", fabricPrefix, header)
	})
}

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

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/require"
)

// Policy enforcement between two real, in-process GoBGP speakers (#717).
//
// The policy-set tests in policy_gobgp_test.go prove GoBGP accepts what the
// speaker installs. They cannot prove GoBGP *applies* it, and it did not:
// GoBGP keeps a per-peer policy assignment only for a route-server client
// (server.go setPeerPolicy) and evaluates every other peer against the
// global assignment, so the per-peer RFC 8212 policy the speaker used to
// attach to each api.Peer was stored nowhere and filtered nothing. These
// tests run a real BGP session over loopback and look at what each speaker
// actually holds.

// sessionWait bounds every wait on the session. The session comes up in about
// two seconds (GoBGP's minimum connect retry); the bound only stops a broken
// session from hanging the run.
// sessionWait bounds a failing run only: every wait returns the moment its
// condition holds. It is sized for the thousand-route convergences, which a
// loaded -race host stretches well past 30 s.
const sessionWait = 2 * time.Minute

// remotePortServer is the real GoBGP adapter with one change: the session it
// opens dials port instead of 179. Two speakers sharing one loopback address
// need distinct ports, and the speaker configuration has no remote-port field
// because nothing in production needs one.
type remotePortServer struct {
	BGPServerInterface
	port uint32
}

// AddPeer points the peer's outgoing connection at the test port.
func (r remotePortServer) AddPeer(ctx context.Context, req *api.AddPeerRequest) error {
	if req.GetPeer().GetTransport() == nil {
		req.Peer.Transport = &api.Transport{}
	}
	req.Peer.Transport.RemotePort = r.port
	return r.BGPServerInterface.AddPeer(ctx, req)
}

// freePort returns a loopback TCP port nothing is listening on.
func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return uint16(port)
}

// loopback is the address both speakers listen on and peer with.
var loopback = netip.MustParseAddr("127.0.0.1")

// sessionPair starts local and remote on loopback and peers them: local
// listens passively, remote dials it. Each config names the other side as its
// only neighbor; sessionPair fills in addresses and ports. It returns once the
// session is established in both directions.
func sessionPair(t *testing.T, local, remote *BGPConfig) (*Speaker, *Speaker) {
	t.Helper()
	ctx := context.Background()

	localPort, remotePort := freePort(t), freePort(t)
	local.ListenAddresses = []netip.Addr{loopback}
	local.ListenPort = localPort
	remote.ListenAddresses = []netip.Addr{loopback}
	remote.ListenPort = remotePort
	local.Neighbors[0].Address = loopback
	local.Neighbors[0].PassiveMode = true
	remote.Neighbors[0].Address = loopback

	localSpeaker, err := NewSpeaker(local, speakerTestLogger())
	require.NoError(t, err)
	remoteSpeaker, err := NewSpeaker(remote, speakerTestLogger(), WithBGPServer(remotePortServer{
		BGPServerInterface: NewGoBGPServerAdapter(server.NewBgpServer()),
		port:               uint32(localPort),
	}))
	require.NoError(t, err)

	for _, s := range []*Speaker{localSpeaker, remoteSpeaker} {
		require.NoError(t, s.Start(ctx))
		t.Cleanup(func() { _ = s.Stop(context.Background()) })
	}
	require.NoError(t, localSpeaker.AddPeer(ctx, &local.Neighbors[0]))
	require.NoError(t, remoteSpeaker.AddPeer(ctx, &remote.Neighbors[0]))

	for _, s := range []*Speaker{localSpeaker, remoteSpeaker} {
		require.Eventually(t, func() bool {
			state, err := s.GetPeerState(ctx, loopback)
			return err == nil && state == PeerStateEstablished
		}, sessionWait, 50*time.Millisecond, "the loopback session never established")
	}
	return localSpeaker, remoteSpeaker
}

// ribEntries lists the destinations in one table of s for family, as GoBGP
// prints them. The adjacency tables are the ones toward the loopback peer.
func ribEntries(t *testing.T, s *Speaker, table api.TableType, family AddressFamily) []string {
	t.Helper()
	req := &api.ListPathRequest{TableType: table, Family: s.addressFamilyToAPI(family)}
	if table != api.TableType_TABLE_TYPE_GLOBAL {
		req.Name = loopback.String()
	}
	var out []string
	require.NoError(t, s.server.ListPath(context.Background(), req, func(d *api.Destination) {
		out = append(out, d.GetPrefix())
	}))
	slices.Sort(out)
	return out
}

// waitForEntry blocks until entry appears in the table, so that what is
// asserted afterwards about its absence elsewhere is not a race. GoBGP
// processes one UPDATE in a single pass of its event loop — adjacency,
// policy, then the global RIB — and ListPath runs on that same loop, so
// once a path is visible in one table its policy outcome is final.
func waitForEntry(t *testing.T, s *Speaker, table api.TableType, family AddressFamily, entry string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return slices.Contains(ribEntries(t, s, table, family), entry)
	}, sessionWait, 50*time.Millisecond, "%s never reached %s", entry, table)
}

// originate adds a locally originated unicast path to s.
func originate(t *testing.T, s *Speaker, prefix, nextHop string) {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	family := AFamilyIPv4Unicast
	if p.Addr().Is6() {
		family = AFamilyIPv6Unicast
	}
	require.NoError(t, s.AddPath(context.Background(), &Path{
		Family:  family,
		Prefix:  p,
		NextHop: netip.MustParseAddr(nextHop),
		Origin:  OriginIGP,
	}))
}

// transitConfig is one side of an eBGP ipv4/ipv6 unicast transit session.
func transitConfig(asn, peerASN uint32, routerID string, policy PeerPolicyConfig) *BGPConfig {
	return &BGPConfig{
		RouterID:        netip.MustParseAddr(routerID),
		ASN:             asn,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast, AFamilyIPv6Unicast},
		Neighbors: []NeighborConfig{{
			Name:            "transit",
			ASN:             peerASN,
			EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast, AFamilyIPv6Unicast},
			Policy:          policy,
		}},
	}
}

// TestPolicySession_TransitUnicast is #717 on a transit session: the
// platform speaker imports only what its allowlist names and exports only
// what its export allowlist names, on both unicast families, while the far
// side offers everything and accepts everything.
func TestPolicySession_TransitUnicast(t *testing.T) {
	platform := transitConfig(64512, 65001, "192.0.2.1", PeerPolicyConfig{
		ImportAllow: []PrefixMatch{
			{Prefix: netip.MustParsePrefix("10.0.0.0/8"), MaxLength: 24},
			{Prefix: netip.MustParsePrefix("2001:db8:1::/48")},
		},
		ExportAllow: []PrefixMatch{
			{Prefix: netip.MustParsePrefix("198.51.100.0/24")},
			{Prefix: netip.MustParsePrefix("2001:db8:100::/48")},
		},
	})
	upstream := transitConfig(65001, 64512, "192.0.2.2", PeerPolicyConfig{
		ImportDefaultAccept: true,
		ExportDefaultAccept: true,
	})
	local, remote := sessionPair(t, platform, upstream)

	// The upstream offers one route outside the allowlist per family, first,
	// then one inside it.
	originate(t, remote, "192.0.2.128/25", "127.0.0.1")
	originate(t, remote, "2001:db8:dead::/48", "::1")
	originate(t, remote, "10.1.0.0/24", "127.0.0.1")
	originate(t, remote, "2001:db8:1::/48", "::1")

	// The platform originates one route outside its export allowlist per
	// family, first, then one inside it.
	originate(t, local, "203.0.113.0/24", "127.0.0.1")
	originate(t, local, "2001:db8:bad::/48", "::1")
	originate(t, local, "198.51.100.0/24", "127.0.0.1")
	originate(t, local, "2001:db8:100::/48", "::1")

	t.Run("import", func(t *testing.T) {
		for _, tc := range []struct {
			family           AddressFamily
			allowed, refused string
		}{
			{AFamilyIPv4Unicast, "10.1.0.0/24", "192.0.2.128/25"},
			{AFamilyIPv6Unicast, "2001:db8:1::/48", "2001:db8:dead::/48"},
		} {
			waitForEntry(t, local, api.TableType_TABLE_TYPE_ADJ_IN, tc.family, tc.refused)
			waitForEntry(t, local, api.TableType_TABLE_TYPE_GLOBAL, tc.family, tc.allowed)
			require.Contains(t, ribEntries(t, local, api.TableType_TABLE_TYPE_ADJ_IN, tc.family), tc.allowed)
			require.NotContains(t, ribEntries(t, local, api.TableType_TABLE_TYPE_GLOBAL, tc.family), tc.refused,
				"%s arrived from the peer and is outside the import allowlist; it must not reach the RIB", tc.refused)
		}
	})

	t.Run("export", func(t *testing.T) {
		for _, tc := range []struct {
			family           AddressFamily
			allowed, refused string
		}{
			{AFamilyIPv4Unicast, "198.51.100.0/24", "203.0.113.0/24"},
			{AFamilyIPv6Unicast, "2001:db8:100::/48", "2001:db8:bad::/48"},
		} {
			waitForEntry(t, remote, api.TableType_TABLE_TYPE_ADJ_IN, tc.family, tc.allowed)
			require.NotContains(t, ribEntries(t, remote, api.TableType_TABLE_TYPE_ADJ_IN, tc.family), tc.refused,
				"%s is outside the export allowlist; the peer must never receive it", tc.refused)
			require.NotContains(t, ribEntries(t, local, api.TableType_TABLE_TYPE_ADJ_OUT, tc.family), tc.refused)
			require.Contains(t, ribEntries(t, local, api.TableType_TABLE_TYPE_GLOBAL, tc.family), tc.refused,
				"the refused route is still the platform's own; only the export to this peer is filtered")
		}
	})
}

// evpnRD is the route distinguisher every test EVPN route carries; only
// the route target decides admission.
var evpnRD = gobgp.NewRouteDistinguisherTwoOctetAS(65000, 100)

// originateEVPN adds a locally originated EVPN MAC/IP Advertisement route
// for mac carrying the route target 65000:rt, and returns the route as GoBGP
// prints it.
func originateEVPN(t *testing.T, s *Speaker, mac string, rt uint32) string {
	t.Helper()
	return originateEVPNWith(t, s, mac, gobgp.NewTwoOctetAsSpecificExtended(gobgp.EC_SUBTYPE_ROUTE_TARGET, 65000, rt, true))
}

// originateEVPNWith adds an EVPN MAC/IP Advertisement route for mac
// carrying routeTarget. It goes straight to the GoBGP server: the speaker's
// own EVPN origination is the overlay work, not this policy, and the policy
// has to hold whatever the RIB is fed.
func originateEVPNWith(t *testing.T, s *Speaker, mac string, routeTarget gobgp.ExtendedCommunityInterface) string {
	t.Helper()
	nlri, err := gobgp.NewEVPNMacIPAdvertisementRoute(evpnRD, gobgp.EthernetSegmentIdentifier{}, 0, mac, netip.Addr{}, []uint32{100})
	require.NoError(t, err)
	reach, err := gobgp.NewPathAttributeMpReachNLRI(gobgp.RF_EVPN, []gobgp.PathNLRI{{NLRI: nlri}}, loopback)
	require.NoError(t, err)
	attrs := []gobgp.PathAttributeInterface{
		gobgp.NewPathAttributeOrigin(gobgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		reach,
		gobgp.NewPathAttributeExtendedCommunities([]gobgp.ExtendedCommunityInterface{routeTarget}),
	}
	path, err := apiutil.NewPath(gobgp.RF_EVPN, nlri, false, attrs, time.Now())
	require.NoError(t, err)
	_, err = s.server.AddPath(context.Background(), &api.AddPathRequest{Path: path})
	require.NoError(t, err)
	return nlri.String()
}

// evpnConfig is one side of an iBGP l2vpn-evpn session.
func evpnConfig(routerID string, neighbor NeighborConfig) *BGPConfig {
	neighbor.Name = "fabric"
	neighbor.ASN = 64512
	neighbor.EnabledFamilies = []AddressFamily{AFamilyEVPN}
	return &BGPConfig{
		RouterID:        netip.MustParseAddr(routerID),
		ASN:             64512,
		EnabledFamilies: []AddressFamily{AFamilyEVPN},
		Neighbors:       []NeighborConfig{neighbor},
	}
}

// acceptEverything is the far side of a session under test: it offers and
// takes whatever it is given, so only the platform's policy filters.
var acceptEverything = PeerPolicyConfig{ImportDefaultAccept: true, ExportDefaultAccept: true}

// TestPolicySession_EVPN is #717 on an l2vpn-evpn session: a route carrying
// a route target outside the allowlist is neither imported nor exported,
// and one carrying an allowed route target is.
func TestPolicySession_EVPN(t *testing.T) {
	platform := evpnConfig("192.0.2.1", NeighborConfig{Policy: PeerPolicyConfig{
		ImportRouteTargets: []string{"65000:100", "4200000000:7", "192.0.2.9:7"},
		ExportRouteTargets: []string{"65000:100"},
	}})
	vtep := evpnConfig("192.0.2.2", NeighborConfig{Policy: acceptEverything})
	local, remote := sessionPair(t, platform, vtep)

	importRefused := originateEVPN(t, remote, "02:00:00:00:00:01", 999)
	importAllowed := originateEVPN(t, remote, "02:00:00:00:00:02", 100)
	exportRefused := originateEVPN(t, local, "02:00:00:00:00:03", 999)
	exportAllowed := originateEVPN(t, local, "02:00:00:00:00:04", 100)

	t.Run("import", func(t *testing.T) {
		waitForEntry(t, local, api.TableType_TABLE_TYPE_ADJ_IN, AFamilyEVPN, importRefused)
		waitForEntry(t, local, api.TableType_TABLE_TYPE_GLOBAL, AFamilyEVPN, importAllowed)
		require.NotContains(t, ribEntries(t, local, api.TableType_TABLE_TYPE_GLOBAL, AFamilyEVPN), importRefused,
			"a route on route target 65000:999 arrived and must not reach the RIB")
	})

	// The other two administrator forms match too. A four-octet AS is the
	// case GoBGP's own parser would have clamped to 65535 (parseRouteTarget).
	t.Run("import, four-octet AS and IPv4 administrators", func(t *testing.T) {
		ipv4RT, err := gobgp.NewIPv4AddressSpecificExtended(gobgp.EC_SUBTYPE_ROUTE_TARGET, netip.MustParseAddr("192.0.2.9"), 7, true)
		require.NoError(t, err)
		clamped := originateEVPNWith(t, remote, "02:00:00:00:00:05",
			gobgp.NewTwoOctetAsSpecificExtended(gobgp.EC_SUBTYPE_ROUTE_TARGET, 65535, 7, true))
		fourOctet := originateEVPNWith(t, remote, "02:00:00:00:00:06",
			gobgp.NewFourOctetAsSpecificExtended(gobgp.EC_SUBTYPE_ROUTE_TARGET, 4200000000, 7, true))
		byAddress := originateEVPNWith(t, remote, "02:00:00:00:00:07", ipv4RT)
		waitForEntry(t, local, api.TableType_TABLE_TYPE_GLOBAL, AFamilyEVPN, fourOctet)
		waitForEntry(t, local, api.TableType_TABLE_TYPE_GLOBAL, AFamilyEVPN, byAddress)
		require.Contains(t, ribEntries(t, local, api.TableType_TABLE_TYPE_ADJ_IN, AFamilyEVPN), clamped)
		require.NotContains(t, ribEntries(t, local, api.TableType_TABLE_TYPE_GLOBAL, AFamilyEVPN), clamped,
			"65535:7 is not 4200000000:7")
	})

	t.Run("export", func(t *testing.T) {
		waitForEntry(t, remote, api.TableType_TABLE_TYPE_ADJ_IN, AFamilyEVPN, exportAllowed)
		require.NotContains(t, ribEntries(t, remote, api.TableType_TABLE_TYPE_ADJ_IN, AFamilyEVPN), exportRefused,
			"a route on route target 65000:999 is outside the export allowlist; the peer must never receive it")
		require.Contains(t, ribEntries(t, local, api.TableType_TABLE_TYPE_GLOBAL, AFamilyEVPN), exportRefused)
	})
}

// TestPolicySession_EVPNHasNoRouteTargetsByDefault pins the RFC 8212
// default for EVPN: a peer configured with no route targets exchanges no
// EVPN routes in either direction.
func TestPolicySession_EVPNHasNoRouteTargetsByDefault(t *testing.T) {
	local, remote := sessionPair(t,
		evpnConfig("192.0.2.1", NeighborConfig{}),
		evpnConfig("192.0.2.2", NeighborConfig{Policy: acceptEverything}))

	offered := originateEVPN(t, remote, "02:00:00:00:00:01", 100)
	withheld := originateEVPN(t, local, "02:00:00:00:00:02", 100)

	waitForEntry(t, local, api.TableType_TABLE_TYPE_ADJ_IN, AFamilyEVPN, offered)
	require.NotContains(t, ribEntries(t, local, api.TableType_TABLE_TYPE_GLOBAL, AFamilyEVPN), offered)

	// The adjacency-out table is computed when it is listed, by running the
	// current export policy over the RIB toward this peer, so it is the
	// deterministic witness here: there is no allowed route to wait for on
	// the far side, which makes "the peer has not received it" a race.
	require.Contains(t, ribEntries(t, local, api.TableType_TABLE_TYPE_GLOBAL, AFamilyEVPN), withheld)
	require.NotContains(t, ribEntries(t, local, api.TableType_TABLE_TYPE_ADJ_OUT, AFamilyEVPN), withheld)
}

// evpnRoutes originates count EVPN routes on the allowed route target.
func evpnRoutes(t *testing.T, s *Speaker, count int) {
	t.Helper()
	for i := range count {
		originateEVPN(t, s, net.HardwareAddr{0x02, 0, 0, 0, byte(i >> 8), byte(i)}.String(), 100)
	}
}

// TestPolicySession_EVPNBeyondTheUnicastLimit is plan §1 defect 5: the
// prefix limit was 1000 for every family, so the 1001st MAC on an EVPN
// session tore the session down. EVPN now has its own, fabric-sized limit.
func TestPolicySession_EVPNBeyondTheUnicastLimit(t *testing.T) {
	const routes = 1500
	require.Greater(t, uint32(routes), DefaultMaxPrefixes, "the test must exceed the unicast limit")

	local, remote := sessionPair(t,
		evpnConfig("192.0.2.1", NeighborConfig{Policy: PeerPolicyConfig{ImportRouteTargets: []string{"65000:100"}}}),
		evpnConfig("192.0.2.2", NeighborConfig{Policy: acceptEverything}))

	evpnRoutes(t, remote, routes)
	require.Eventually(t, func() bool {
		return len(ribEntries(t, local, api.TableType_TABLE_TYPE_GLOBAL, AFamilyEVPN)) == routes
	}, sessionWait, 50*time.Millisecond, "all %d EVPN routes must be accepted", routes)

	state, err := local.GetPeerState(context.Background(), loopback)
	require.NoError(t, err)
	require.Equal(t, PeerStateEstablished, state, "the session must survive more than %d EVPN routes", DefaultMaxPrefixes)
}

// TestPolicySession_EVPNLimitIsEnforced is the other half: the EVPN limit
// is a limit. A peer that sends more than its configured max-evpn-prefixes
// loses the session.
func TestPolicySession_EVPNLimitIsEnforced(t *testing.T) {
	local, remote := sessionPair(t,
		evpnConfig("192.0.2.1", NeighborConfig{
			MaxEVPNPrefixes: 100,
			Policy:          PeerPolicyConfig{ImportRouteTargets: []string{"65000:100"}},
		}),
		evpnConfig("192.0.2.2", NeighborConfig{Policy: acceptEverything}))

	evpnRoutes(t, remote, 150)
	require.Eventually(t, func() bool {
		state, err := local.GetPeerState(context.Background(), loopback)
		return err == nil && state != PeerStateEstablished
	}, sessionWait, 10*time.Millisecond, "150 routes against a limit of 100 must tear the session down")
}

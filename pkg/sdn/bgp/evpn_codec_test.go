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
	"net"
	"net/netip"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The codec fixtures: VTEP 192.0.2.11 in overlay ASN 65000, an L3VNI whose
// top bits are set so that any shift of the label would be visible.
var (
	codecVTEP      = netip.MustParseAddr("192.0.2.11")
	codecRD        = RouteDistinguisher{Admin: codecVTEP, Index: 1}
	codecRouterMAC = net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	codecHostMAC   = net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
)

const (
	codecL2VNI uint32 = 10100
	codecL3VNI uint32 = 0xfedcba
)

// mustRT derives the overlay route target of vni.
func mustRT(t testing.TB, vni uint32) RouteTarget {
	t.Helper()
	rt, err := AutoRouteTarget(65000, 0, vni)
	require.NoError(t, err)
	return rt
}

// testIRBRoute is a symmetric-IRB Type-2 route of a moved MAC.
func testIRBRoute() *EVPNRouteData {
	return &EVPNRouteData{
		Type: EVPNTypeMACIPAdvertisement,
		RD:   codecRD,
		RouteTargets: []RouteTarget{
			{AS: 65000, Value: 1<<28 | codecL2VNI},
			{AS: 65000, Value: 1<<28 | codecL3VNI},
		},
		MACIP: &MACIPEntry{
			MAC:      codecHostMAC,
			IP:       netip.MustParseAddr("10.1.0.10"),
			VNI:      codecL2VNI,
			L3VNI:    codecL3VNI,
			VTEPIP:   codecVTEP,
			Sequence: 3,
		},
		NextHop:   codecVTEP,
		RouterMAC: codecRouterMAC,
	}
}

// testIMETRoute is a Type-3 route.
func testIMETRoute(t testing.TB) *EVPNRouteData {
	return &EVPNRouteData{
		Type:         EVPNTypeInclusiveMulticast,
		RD:           codecRD,
		RouteTargets: []RouteTarget{mustRT(t, codecL2VNI)},
		IMET:         &IMETEntry{VNI: codecL2VNI, VTEPIP: codecVTEP},
		NextHop:      codecVTEP,
	}
}

// testPrefixRoute is an interface-less Type-5 route.
func testPrefixRoute(t testing.TB, prefix string) *EVPNRouteData {
	return &EVPNRouteData{
		Type:         EVPNTypeIPPrefix,
		RD:           RouteDistinguisher{Admin: codecVTEP, Index: 2},
		RouteTargets: []RouteTarget{mustRT(t, codecL3VNI)},
		PrefixData:   &PrefixRoute{Prefix: netip.MustParsePrefix(prefix), VNI: codecL3VNI, VTEPIP: codecVTEP},
		NextHop:      codecVTEP,
		RouterMAC:    codecRouterMAC,
	}
}

// roundTrip encodes route and decodes the result.
func roundTrip(t *testing.T, route *EVPNRouteData) *EVPNRouteData {
	t.Helper()
	path, err := encodeEVPNPath(route)
	require.NoError(t, err)
	decoded, err := decodeEVPNPath(path)
	require.NoError(t, err)
	return decoded
}

// nativeAttribute returns the attribute of type T on an encoded path.
func nativeAttribute[T gobgp.PathAttributeInterface](t *testing.T, path *api.Path) T {
	t.Helper()
	attrs, err := apiutil.GetNativePathAttributes(path)
	require.NoError(t, err)
	for _, attr := range attrs {
		if typed, ok := attr.(T); ok {
			return typed
		}
	}
	var zero T
	t.Fatalf("no %T on the path", zero)
	return zero
}

// rawEVPNPath builds a path from native parts, for the malformed cases the
// encoder refuses to produce.
func rawEVPNPath(t *testing.T, nlri *gobgp.EVPNNLRI, nextHop netip.Addr, attrs ...gobgp.PathAttributeInterface) *api.Path {
	t.Helper()
	reach, err := gobgp.NewPathAttributeMpReachNLRI(gobgp.RF_EVPN, []gobgp.PathNLRI{{NLRI: nlri}}, nextHop)
	require.NoError(t, err)
	path, err := apiutil.NewPath(gobgp.RF_EVPN, nlri, false, append([]gobgp.PathAttributeInterface{reach}, attrs...), time.Now())
	require.NoError(t, err)
	return path
}

// communities wraps extended communities as an attribute.
func communities(c ...gobgp.ExtendedCommunityInterface) gobgp.PathAttributeInterface {
	return gobgp.NewPathAttributeExtendedCommunities(c)
}

func TestEVPNCodec_MACIP(t *testing.T) {
	t.Run("symmetric IRB round trip", func(t *testing.T) {
		route := testIRBRoute()
		got := roundTrip(t, route)
		assert.Equal(t, route.Key(), got.Key())
		assert.Equal(t, codecRD, got.RD)
		assert.ElementsMatch(t, route.RouteTargets, got.RouteTargets)
		assert.Equal(t, codecL2VNI, got.MACIP.VNI, "label 1 is the L2VNI")
		assert.Equal(t, codecL3VNI, got.MACIP.L3VNI, "label 2 is the L3VNI")
		assert.Equal(t, codecRouterMAC, got.RouterMAC)
		assert.Equal(t, uint32(3), got.MACIP.Sequence)
		assert.Equal(t, codecVTEP, got.MACIP.VTEPIP)
		assert.Equal(t, codecVTEP, got.NextHop)
		assert.False(t, got.IsWithdraw)
	})

	t.Run("labels are raw 24-bit VNIs on the wire", func(t *testing.T) {
		path, err := encodeEVPNPath(testIRBRoute())
		require.NoError(t, err)
		nlri, err := apiutil.GetNativeNlri(path)
		require.NoError(t, err)
		wire, err := nlri.Serialize()
		require.NoError(t, err)
		labels := wire[len(wire)-6:]
		assert.Equal(t, []byte{0x00, 0x27, 0x74}, labels[:3], "L2VNI 10100, unshifted")
		assert.Equal(t, []byte{0xfe, 0xdc, 0xba}, labels[3:], "L3VNI 0xfedcba, unshifted")
	})

	t.Run("VXLAN encapsulation community", func(t *testing.T) {
		path, err := encodeEVPNPath(testIRBRoute())
		require.NoError(t, err)
		ext := nativeAttribute[*gobgp.PathAttributeExtendedCommunities](t, path)
		var encap *gobgp.EncapExtended
		for _, c := range ext.Value {
			if e, ok := c.(*gobgp.EncapExtended); ok {
				encap = e
			}
		}
		require.NotNil(t, encap)
		assert.Equal(t, gobgp.TUNNEL_TYPE_VXLAN, encap.TunnelType)
	})

	t.Run("MAC only, no IRB, no move", func(t *testing.T) {
		route := &EVPNRouteData{
			Type:         EVPNTypeMACIPAdvertisement,
			RD:           codecRD,
			RouteTargets: []RouteTarget{mustRT(t, codecL2VNI)},
			MACIP:        &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI},
			NextHop:      codecVTEP,
		}
		got := roundTrip(t, route)
		assert.False(t, got.MACIP.IP.IsValid())
		assert.Zero(t, got.MACIP.L3VNI)
		assert.Zero(t, got.MACIP.Sequence)
		assert.Nil(t, got.RouterMAC)
	})

	t.Run("withdrawal keeps the NLRI identity", func(t *testing.T) {
		route := testIRBRoute()
		route.IsWithdraw = true
		path, err := encodeEVPNPath(route)
		require.NoError(t, err)
		got, err := decodeEVPNPath(path)
		require.NoError(t, err)
		assert.True(t, got.IsWithdraw)
		assert.Equal(t, route.Key(), got.Key())
	})
}

func TestEVPNCodec_IMET(t *testing.T) {
	route := testIMETRoute(t)
	got := roundTrip(t, route)
	assert.Equal(t, route.Key(), got.Key())
	assert.Equal(t, codecL2VNI, got.IMET.VNI)
	assert.Equal(t, codecVTEP, got.IMET.VTEPIP)

	t.Run("PMSI tunnel is ingress replication with the raw VNI label", func(t *testing.T) {
		path, err := encodeEVPNPath(route)
		require.NoError(t, err)
		pmsi := nativeAttribute[*gobgp.PathAttributePmsiTunnel](t, path)
		assert.Equal(t, gobgp.PMSI_TUNNEL_TYPE_INGRESS_REPL, pmsi.TunnelType)
		wire, err := pmsi.Serialize()
		require.NoError(t, err)
		// flags, type, length; then leaf flag, tunnel type, 3-byte label.
		assert.Equal(t, []byte{0x00, 0x27, 0x74}, wire[5:8], "the PMSI label is the VNI, unshifted")
	})

	t.Run("the originator names the route, the PMSI tunnel the endpoint", func(t *testing.T) {
		endpoint := netip.MustParseAddr("192.0.2.99")
		route := testIMETRoute(t)
		route.IMET.OriginatorIP = codecVTEP
		route.IMET.VTEPIP = endpoint
		got := roundTrip(t, route)
		assert.Equal(t, codecVTEP, got.IMET.OriginatorIP)
		assert.Equal(t, endpoint, got.IMET.VTEPIP)

		route.IsWithdraw = true
		path, err := encodeEVPNPath(route)
		require.NoError(t, err)
		gone, err := decodeEVPNPath(path)
		require.NoError(t, err)
		assert.True(t, gone.IsWithdraw)
		assert.Equal(t, got.Key(), gone.Key(), "the withdrawal names the route it withdraws")
	})
}

func TestEVPNCodec_Prefix(t *testing.T) {
	for _, prefix := range []string{"10.1.0.0/24", "2001:db8:1::/64"} {
		t.Run(prefix, func(t *testing.T) {
			route := testPrefixRoute(t, prefix)
			got := roundTrip(t, route)
			assert.Equal(t, route.Key(), got.Key())
			assert.Equal(t, netip.MustParsePrefix(prefix), got.PrefixData.Prefix)
			assert.Equal(t, codecL3VNI, got.PrefixData.VNI)
			assert.False(t, got.PrefixData.GatewayIP.IsValid(), "interface-less")
			assert.Equal(t, codecRouterMAC, got.RouterMAC)
			assert.Equal(t, codecVTEP, got.PrefixData.VTEPIP)
		})
	}

	t.Run("gateway model needs no Router's MAC", func(t *testing.T) {
		route := testPrefixRoute(t, "10.2.0.0/16")
		route.RouterMAC = nil
		route.PrefixData.GatewayIP = netip.MustParseAddr("10.2.0.1")
		got := roundTrip(t, route)
		assert.Equal(t, route.PrefixData.GatewayIP, got.PrefixData.GatewayIP)
		assert.Nil(t, got.RouterMAC)
	})
}

func TestEncodeEVPNPath_Errors(t *testing.T) {
	for name, mutate := range map[string]func(r *EVPNRouteData){
		"unsupported type":           func(r *EVPNRouteData) { r.Type = EVPNTypeEthernetSegment },
		"no next hop":                func(r *EVPNRouteData) { r.NextHop = netip.Addr{} },
		"unspecified next hop":       func(r *EVPNRouteData) { r.NextHop = netip.IPv4Unspecified() },
		"no route target":            func(r *EVPNRouteData) { r.RouteTargets = nil },
		"IPv6 RD administrator":      func(r *EVPNRouteData) { r.RD.Admin = netip.MustParseAddr("2001:db8::1") },
		"nil entry":                  func(r *EVPNRouteData) { r.MACIP = nil },
		"group MAC":                  func(r *EVPNRouteData) { r.MACIP.MAC = net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 1} },
		"short MAC":                  func(r *EVPNRouteData) { r.MACIP.MAC = net.HardwareAddr{0x02, 0} },
		"zero L2VNI":                 func(r *EVPNRouteData) { r.MACIP.VNI = 0 },
		"L2VNI beyond 24 bits":       func(r *EVPNRouteData) { r.MACIP.VNI = MaxVNI + 1 },
		"L3VNI beyond 24 bits":       func(r *EVPNRouteData) { r.MACIP.L3VNI = MaxVNI + 1 },
		"L3VNI without Router's MAC": func(r *EVPNRouteData) { r.RouterMAC = nil },
	} {
		t.Run(name, func(t *testing.T) {
			route := testIRBRoute()
			mutate(route)
			_, err := encodeEVPNPath(route)
			require.Error(t, err)
		})
	}

	t.Run("nil route", func(t *testing.T) {
		_, err := encodeEVPNPath(nil)
		var nilEntry ErrEntryNil
		require.ErrorAs(t, err, &nilEntry)
	})

	t.Run("IMET", func(t *testing.T) {
		for name, mutate := range map[string]func(r *EVPNRouteData){
			"nil entry": func(r *EVPNRouteData) { r.IMET = nil },
			"zero VNI":  func(r *EVPNRouteData) { r.IMET.VNI = 0 },
			"no VTEP":   func(r *EVPNRouteData) { r.IMET.VTEPIP = netip.Addr{} },
		} {
			t.Run(name, func(t *testing.T) {
				route := testIMETRoute(t)
				mutate(route)
				_, err := encodeEVPNPath(route)
				require.Error(t, err)
			})
		}
	})

	t.Run("prefix", func(t *testing.T) {
		for name, mutate := range map[string]func(r *EVPNRouteData){
			"nil entry":                 func(r *EVPNRouteData) { r.PrefixData = nil },
			"invalid prefix":            func(r *EVPNRouteData) { r.PrefixData.Prefix = netip.Prefix{} },
			"zero VNI":                  func(r *EVPNRouteData) { r.PrefixData.VNI = 0 },
			"interface-less, no MAC":    func(r *EVPNRouteData) { r.RouterMAC = nil },
			"gateway of another family": func(r *EVPNRouteData) { r.PrefixData.GatewayIP = netip.MustParseAddr("2001:db8::1") },
		} {
			t.Run(name, func(t *testing.T) {
				route := testPrefixRoute(t, "10.1.0.0/24")
				mutate(route)
				_, err := encodeEVPNPath(route)
				require.Error(t, err)
			})
		}
	})
}

func TestDecodeEVPNPath_Dropped(t *testing.T) {
	type2 := func(rd gobgp.RouteDistinguisherInterface) *gobgp.EVPNNLRI {
		nlri, err := gobgp.NewEVPNMacIPAdvertisementRoute(rd, gobgp.EthernetSegmentIdentifier{}, 0, codecHostMAC.String(), netip.Addr{}, []uint32{codecL2VNI})
		require.NoError(t, err)
		return nlri
	}
	evpnFamily := &api.Family{Afi: api.Family_AFI_L2VPN, Safi: api.Family_SAFI_EVPN}

	t.Run("nil path", func(t *testing.T) {
		_, err := decodeEVPNPath(nil)
		require.Error(t, err)
	})

	t.Run("NLRI does not parse", func(t *testing.T) {
		route, err := decodeEVPNPath(&api.Path{Family: evpnFamily, NlriBinary: []byte{2, 40, 0}})
		require.Error(t, err)
		assert.Nil(t, route, "without an NLRI there is nothing to withdraw")
	})

	t.Run("not EVPN", func(t *testing.T) {
		path := &api.Path{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Nlri:   &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{Prefix: "10.0.0.0", PrefixLen: 8}}},
		}
		_, err := decodeEVPNPath(path)
		var failed ErrRouteDecodingFailed
		require.ErrorAs(t, err, &failed)
	})

	t.Run("RD other than Type-1 (RFC 7432 §7.9)", func(t *testing.T) {
		path := rawEVPNPath(t, type2(gobgp.NewRouteDistinguisherTwoOctetAS(65000, 1)), codecVTEP,
			communities(mustRT(t, codecL2VNI).native(), gobgp.NewEncapExtended(gobgp.TUNNEL_TYPE_VXLAN)))
		route, err := decodeEVPNPath(path)
		require.Error(t, err)
		assert.Nil(t, route)
	})

	t.Run("route type the overlay does not speak", func(t *testing.T) {
		// A Type-4 Ethernet Segment route: RD 192.0.2.11:1, zero ESI, IPv4
		// originator.
		nlri := []byte{4, 23, 0, 1, 192, 0, 2, 11, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 192, 0, 2, 11}
		_, err := decodeEVPNPath(&api.Path{Family: evpnFamily, NlriBinary: nlri})
		var unsupported ErrUnsupportedRouteType
		require.ErrorAs(t, err, &unsupported)
		assert.Equal(t, EVPNTypeEthernetSegment, unsupported.RouteType)
	})
}

// TestDecodeEVPNPath_TreatAsWithdraw is RFC 7606 §2: a route whose NLRI
// parses but whose attributes are unusable withdraws its NLRI rather than
// resetting the session or being kept.
func TestDecodeEVPNPath_TreatAsWithdraw(t *testing.T) {
	rd, err := codecRD.native()
	require.NoError(t, err)
	macIP := func(labels ...uint32) *gobgp.EVPNNLRI {
		nlri, err := gobgp.NewEVPNMacIPAdvertisementRoute(rd, gobgp.EthernetSegmentIdentifier{}, 0, codecHostMAC.String(), netip.Addr{}, labels)
		require.NoError(t, err)
		return nlri
	}
	imet, err := gobgp.NewEVPNMulticastEthernetTagRoute(rd, 0, codecVTEP)
	require.NoError(t, err)
	prefix, err := gobgp.NewEVPNIPPrefixRoute(rd, gobgp.EthernetSegmentIdentifier{}, 0, 24, netip.MustParseAddr("10.1.0.0"), netip.IPv4Unspecified(), codecL3VNI)
	require.NoError(t, err)
	tunnel, err := gobgp.NewIngressReplTunnelID(codecVTEP)
	require.NoError(t, err)

	rt := mustRT(t, codecL2VNI).native()
	vxlan := gobgp.NewEncapExtended(gobgp.TUNNEL_TYPE_VXLAN)
	routerMAC := gobgp.NewRoutersMacExtended(codecRouterMAC.String())

	for name, path := range map[string]*api.Path{
		"no VXLAN encapsulation":                     rawEVPNPath(t, macIP(codecL2VNI), codecVTEP, communities(rt)),
		"unspecified next hop":                       rawEVPNPath(t, macIP(codecL2VNI), netip.IPv4Unspecified(), communities(rt, vxlan)),
		"zero L2VNI label":                           rawEVPNPath(t, macIP(0), codecVTEP, communities(rt, vxlan)),
		"L3VNI without Router's MAC":                 rawEVPNPath(t, macIP(codecL2VNI, codecL3VNI), codecVTEP, communities(rt, vxlan)),
		"group-address Router's MAC":                 rawEVPNPath(t, macIP(codecL2VNI, codecL3VNI), codecVTEP, communities(rt, vxlan, gobgp.NewRoutersMacExtended("01:00:5e:00:00:01"))),
		"two Router's MACs":                          rawEVPNPath(t, macIP(codecL2VNI, codecL3VNI), codecVTEP, communities(rt, vxlan, routerMAC, gobgp.NewRoutersMacExtended("02:00:00:00:00:99"))),
		"two MAC Mobility sequences":                 rawEVPNPath(t, macIP(codecL2VNI), codecVTEP, communities(rt, vxlan, gobgp.NewMacMobilityExtended(1, false), gobgp.NewMacMobilityExtended(2, false))),
		"IMET without PMSI tunnel":                   rawEVPNPath(t, imet, codecVTEP, communities(rt, vxlan)),
		"IMET with a zero PMSI label":                rawEVPNPath(t, imet, codecVTEP, communities(rt, vxlan), gobgp.NewPathAttributePmsiTunnel(gobgp.PMSI_TUNNEL_TYPE_INGRESS_REPL, false, 0, tunnel)),
		"interface-less prefix without Router's MAC": rawEVPNPath(t, prefix, codecVTEP, communities(rt, vxlan)),
	} {
		t.Run(name, func(t *testing.T) {
			route, err := decodeEVPNPath(path)
			var withdraw ErrTreatAsWithdraw
			require.ErrorAs(t, err, &withdraw)
			assert.NotEmpty(t, withdraw.Error())
			require.NotNil(t, route, "the NLRI parsed, so the route is withdrawn by it")
			assert.True(t, route.IsWithdraw)
			assert.Equal(t, codecRD, route.RD)
		})
	}

	t.Run("one MAC Mobility sequence repeated is not a conflict", func(t *testing.T) {
		route, err := decodeEVPNPath(rawEVPNPath(t, macIP(codecL2VNI), codecVTEP,
			communities(rt, vxlan, gobgp.NewMacMobilityExtended(4, false), gobgp.NewMacMobilityExtended(4, false))))
		require.NoError(t, err)
		assert.Equal(t, uint32(4), route.MACIP.Sequence)
	})
}

func TestEVPNRouteData_KeyAndClone(t *testing.T) {
	route := testIRBRoute()
	clone := route.Clone()
	assert.Equal(t, route, clone)

	clone.MACIP.MAC[5] = 0xff
	clone.RouterMAC[5] = 0xff
	clone.RouteTargets[0].Value = 1
	assert.Equal(t, codecHostMAC, route.MACIP.MAC, "the clone shares no MAC")
	assert.Equal(t, codecRouterMAC, route.RouterMAC)
	assert.Equal(t, uint32(1<<28|codecL2VNI), route.RouteTargets[0].Value)

	t.Run("key ignores labels and attributes", func(t *testing.T) {
		moved := testIRBRoute()
		moved.MACIP.Sequence = 9
		moved.MACIP.L3VNI = 0
		moved.RouteTargets = nil
		assert.Equal(t, route.Key(), moved.Key())

		other := testIRBRoute()
		other.RD.Index = 2
		assert.NotEqual(t, route.Key(), other.Key(), "the RD is part of the NLRI")
	})

	t.Run("nil", func(t *testing.T) {
		var nilRoute *EVPNRouteData
		assert.Nil(t, nilRoute.Clone())
		assert.Empty(t, nilRoute.Key())
		assert.False(t, (*MACIPEntry)(nil).HasIP())
		assert.True(t, route.MACIP.HasIP())
	})
}

// FuzzDecodeEVPNPath feeds arbitrary NLRI and attribute bytes to the
// decoder. It must never panic, and a route it accepts must be one the
// encoder can send again under the same NLRI.
func FuzzDecodeEVPNPath(f *testing.F) {
	for _, route := range []*EVPNRouteData{testIRBRoute(), testIMETRoute(f), testPrefixRoute(f, "10.1.0.0/24"), testPrefixRoute(f, "2001:db8::/32")} {
		path, err := encodeEVPNPath(route)
		require.NoError(f, err)
		nlri, err := apiutil.GetNativeNlri(path)
		require.NoError(f, err)
		nlriBytes, err := nlri.Serialize()
		require.NoError(f, err)
		attrs, err := apiutil.GetNativePathAttributes(path)
		require.NoError(f, err)
		seeds := make([][]byte, 3)
		for i, attr := range attrs[1:] {
			if i < len(seeds) {
				seeds[i], err = attr.Serialize()
				require.NoError(f, err)
			}
		}
		f.Add(nlriBytes, seeds[0], seeds[1], seeds[2])
	}

	family := &api.Family{Afi: api.Family_AFI_L2VPN, Safi: api.Family_SAFI_EVPN}
	f.Fuzz(func(t *testing.T, nlri, a, b, c []byte) {
		var pattrs [][]byte
		for _, attr := range [][]byte{a, b, c} {
			if len(attr) > 0 {
				pattrs = append(pattrs, attr)
			}
		}
		route, err := decodeEVPNPath(&api.Path{Family: family, NlriBinary: nlri, PattrsBinary: pattrs})
		if err != nil || route.IsWithdraw || len(route.RouteTargets) == 0 {
			return
		}
		path, err := encodeEVPNPath(route)
		require.NoError(t, err, "an accepted route must encode again")
		again, err := decodeEVPNPath(path)
		require.NoError(t, err)
		require.Equal(t, route.Key(), again.Key())
	})
}

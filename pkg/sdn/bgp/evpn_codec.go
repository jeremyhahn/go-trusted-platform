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
	"strconv"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// The EVPN routes of a VXLAN overlay (RFC 7432, RFC 8365, RFC 9135,
// RFC 9136) and their translation to and from GoBGP's native packet types.
// A VNI travels as a raw 24-bit label; there is no MPLS shift.

// MACIPEntry is the content of a Type-2 MAC/IP Advertisement route.
type MACIPEntry struct {
	// MAC is the host's hardware address.
	MAC net.HardwareAddr

	// IP is the host's address; the zero value advertises the MAC alone.
	IP netip.Addr

	// VNI is the L2VNI, label 1.
	VNI uint32

	// L3VNI is the L3VNI of symmetric IRB, label 2 (RFC 9135 §5.1); zero
	// when the route carries no IP-VRF.
	L3VNI uint32

	// VTEPIP is the VTEP the host sits behind: the route's next hop.
	VTEPIP netip.Addr

	// Sequence is the MAC Mobility sequence number (RFC 7432 §15); zero
	// sends no MAC Mobility community.
	Sequence uint32

	// EthernetTagID is zero for the VLAN-based service of RFC 8365.
	EthernetTagID uint32
}

// HasIP reports whether the entry binds an IP address.
func (e *MACIPEntry) HasIP() bool {
	return e != nil && e.IP.IsValid()
}

// Clone returns a deep copy of the entry.
func (e *MACIPEntry) Clone() *MACIPEntry {
	if e == nil {
		return nil
	}
	clone := *e
	clone.MAC = cloneMAC(e.MAC)
	return &clone
}

// IMETEntry is the content of a Type-3 Inclusive Multicast Ethernet Tag
// route: a VTEP's membership of a VNI, and so its place on the VNI's
// ingress-replication list.
type IMETEntry struct {
	// VNI is the L2VNI, carried as the PMSI tunnel label.
	VNI uint32

	// VTEPIP is the ingress-replication tunnel endpoint.
	VTEPIP netip.Addr

	// OriginatorIP is the originating router's address in the NLRI, which
	// names the route; a received route's tunnel endpoint may differ from
	// it. Zero means VTEPIP.
	OriginatorIP netip.Addr

	// EthernetTagID is zero for the VLAN-based service of RFC 8365.
	EthernetTagID uint32
}

// originator returns the address that names the route.
func (e *IMETEntry) originator() netip.Addr {
	if e.OriginatorIP.IsValid() {
		return e.OriginatorIP
	}
	return e.VTEPIP
}

// Clone returns a copy of the entry.
func (e *IMETEntry) Clone() *IMETEntry {
	if e == nil {
		return nil
	}
	clone := *e
	return &clone
}

// PrefixRoute is the content of a Type-5 IP Prefix route in the
// interface-less model of RFC 9136 §4.4.1: no gateway IP, the router's MAC
// in its community.
type PrefixRoute struct {
	// Prefix is the advertised prefix.
	Prefix netip.Prefix

	// VNI is the L3VNI of the IP-VRF.
	VNI uint32

	// GatewayIP is the overlay gateway; the zero value encodes the
	// interface-less model.
	GatewayIP netip.Addr

	// VTEPIP is the advertising VTEP: the route's next hop.
	VTEPIP netip.Addr

	// EthernetTagID is zero for the VLAN-based service of RFC 8365.
	EthernetTagID uint32
}

// Clone returns a copy of the route.
func (r *PrefixRoute) Clone() *PrefixRoute {
	if r == nil {
		return nil
	}
	clone := *r
	return &clone
}

// EVPNRouteData is one EVPN route: exactly one of MACIP, IMET and
// PrefixData is set, matching Type.
type EVPNRouteData struct {
	// Type is the EVPN route type.
	Type EVPNRouteType

	// RD is the originator's Type-1 route distinguisher.
	RD RouteDistinguisher

	// RouteTargets are the route's two-octet AS route targets; route
	// targets of any other form are not carried.
	RouteTargets []RouteTarget

	// MACIP holds a Type-2 route.
	MACIP *MACIPEntry

	// IMET holds a Type-3 route.
	IMET *IMETEntry

	// PrefixData holds a Type-5 route.
	PrefixData *PrefixRoute

	// NextHop is the BGP next hop: the originating VTEP.
	NextHop netip.Addr

	// RouterMAC is the Router's MAC extended community (RFC 9135 §8.1),
	// the inner destination MAC of symmetric-IRB traffic to the VTEP.
	RouterMAC net.HardwareAddr

	// IsWithdraw marks a withdrawal, including a route treated as
	// withdraw under RFC 7606.
	IsWithdraw bool

	// ReceivedAt is when the route was received.
	ReceivedAt time.Time
}

// Key identifies the route by its NLRI, the identity BGP replaces and
// withdraws by: type, RD and the type's own key fields. Labels and
// attributes are not part of it.
func (r *EVPNRouteData) Key() string {
	if r == nil {
		return ""
	}
	key := strconv.FormatUint(uint64(r.Type), 10) + "|" + r.RD.String()
	switch {
	case r.MACIP != nil:
		return key + "|" + strconv.FormatUint(uint64(r.MACIP.EthernetTagID), 10) + "|" + r.MACIP.MAC.String() + "|" + r.MACIP.IP.String()
	case r.IMET != nil:
		return key + "|" + strconv.FormatUint(uint64(r.IMET.EthernetTagID), 10) + "|" + r.IMET.originator().String()
	case r.PrefixData != nil:
		return key + "|" + strconv.FormatUint(uint64(r.PrefixData.EthernetTagID), 10) + "|" + r.PrefixData.Prefix.String()
	}
	return key
}

// Clone returns a deep copy of the route.
func (r *EVPNRouteData) Clone() *EVPNRouteData {
	if r == nil {
		return nil
	}
	clone := *r
	if r.RouteTargets != nil {
		clone.RouteTargets = append([]RouteTarget(nil), r.RouteTargets...)
	}
	clone.MACIP = r.MACIP.Clone()
	clone.IMET = r.IMET.Clone()
	clone.PrefixData = r.PrefixData.Clone()
	clone.RouterMAC = cloneMAC(r.RouterMAC)
	return &clone
}

// hasRouteTarget reports whether the route carries rt.
func (r *EVPNRouteData) hasRouteTarget(rt RouteTarget) bool {
	for _, carried := range r.RouteTargets {
		if carried == rt {
			return true
		}
	}
	return false
}

// evpnEncoding is the type-specific part of an encoded route.
type evpnEncoding struct {
	nlri        *gobgp.EVPNNLRI
	communities []gobgp.ExtendedCommunityInterface
	attributes  []gobgp.PathAttributeInterface
}

// evpnAttributes are the attributes of a received route the overlay reads.
type evpnAttributes struct {
	nextHop     netip.Addr
	vxlan       bool
	routeTarget []RouteTarget
	routerMACs  []net.HardwareAddr
	sequences   []uint32
	pmsi        *gobgp.PathAttributePmsiTunnel
}

// evpnRouteCodec is the per-route-type part of encoding and decoding.
type evpnRouteCodec struct {
	// encode builds the NLRI and the type-specific attributes.
	encode func(r *EVPNRouteData, rd gobgp.RouteDistinguisherInterface) (*evpnEncoding, error)

	// decodeNLRI fills the route from its NLRI. An error drops the route:
	// without its key fields it cannot even be withdrawn.
	decodeNLRI func(r *EVPNRouteData, data gobgp.EVPNRouteTypeInterface) error

	// validate checks a received route against its attributes and fills
	// the attribute-borne fields. A non-empty reason treats the route as
	// withdraw.
	validate func(r *EVPNRouteData, attrs *evpnAttributes) string
}

// evpnCodecs are the route types the overlay speaks. Type-1 and Type-4
// (multihoming) are not used by a single-homed VTEP.
var evpnCodecs = map[EVPNRouteType]evpnRouteCodec{
	EVPNTypeMACIPAdvertisement: {encode: encodeMACIP, decodeNLRI: decodeMACIPNLRI, validate: validateMACIP},
	EVPNTypeInclusiveMulticast: {encode: encodeIMET, decodeNLRI: decodeIMETNLRI, validate: validateIMET},
	EVPNTypeIPPrefix:           {encode: encodePrefix, decodeNLRI: decodePrefixNLRI, validate: validatePrefix},
}

// encodeEVPNPath builds the GoBGP path of an EVPN route: its NLRI, the
// MP_REACH next hop, the route targets, the VXLAN encapsulation community
// (RFC 8365 §5.1.3) and the type's own attributes.
func encodeEVPNPath(r *EVPNRouteData) (*api.Path, error) {
	if r == nil {
		return nil, ErrEntryNil{EntryType: "EVPNRouteData"}
	}
	codec, ok := evpnCodecs[r.Type]
	if !ok {
		return nil, ErrUnsupportedRouteType{RouteType: r.Type}
	}
	if !r.NextHop.IsValid() || r.NextHop.IsUnspecified() {
		return nil, ErrRouteEncodingFailed{RouteType: r.Type, Cause: ErrInvalidIP{IP: r.NextHop, Reason: "the next hop is the originating VTEP"}}
	}
	if len(r.RouteTargets) == 0 {
		return nil, ErrInvalidEVPNRoute{RouteType: r.Type, Reason: "a route without a route target is imported nowhere"}
	}
	rd, err := r.RD.native()
	if err != nil {
		return nil, ErrRouteEncodingFailed{RouteType: r.Type, Cause: err}
	}
	encoding, err := codec.encode(r, rd)
	if err != nil {
		return nil, ErrRouteEncodingFailed{RouteType: r.Type, Cause: err}
	}

	communities := make([]gobgp.ExtendedCommunityInterface, 0, len(r.RouteTargets)+len(encoding.communities)+1)
	for _, rt := range r.RouteTargets {
		communities = append(communities, rt.native())
	}
	communities = append(communities, encoding.communities...)
	communities = append(communities, gobgp.NewEncapExtended(gobgp.TUNNEL_TYPE_VXLAN))

	reach, err := gobgp.NewPathAttributeMpReachNLRI(gobgp.RF_EVPN, []gobgp.PathNLRI{{NLRI: encoding.nlri}}, r.NextHop)
	if err != nil {
		return nil, ErrRouteEncodingFailed{RouteType: r.Type, Cause: err}
	}
	attrs := append([]gobgp.PathAttributeInterface{
		gobgp.NewPathAttributeOrigin(gobgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		reach,
		gobgp.NewPathAttributeExtendedCommunities(communities),
	}, encoding.attributes...)

	path, err := apiutil.NewPath(gobgp.RF_EVPN, encoding.nlri, r.IsWithdraw, attrs, time.Now())
	if err != nil {
		return nil, ErrRouteEncodingFailed{RouteType: r.Type, Cause: err}
	}
	return path, nil
}

// encodeMACIP builds a Type-2 route. Symmetric IRB adds the L3VNI as the
// second label and the Router's MAC (RFC 9135 §5.1); a moved MAC carries
// its sequence number (RFC 7432 §15).
func encodeMACIP(r *EVPNRouteData, rd gobgp.RouteDistinguisherInterface) (*evpnEncoding, error) {
	e := r.MACIP
	if e == nil {
		return nil, ErrInvalidEVPNRoute{RouteType: r.Type, Reason: "the MAC/IP entry is nil"}
	}
	if err := validateUnicastMAC(e.MAC); err != nil {
		return nil, err
	}
	if err := validateVNI(e.VNI); err != nil {
		return nil, err
	}
	labels := []uint32{e.VNI}
	var communities []gobgp.ExtendedCommunityInterface
	if e.L3VNI != 0 {
		if err := validateVNI(e.L3VNI); err != nil {
			return nil, err
		}
		if err := validateUnicastMAC(r.RouterMAC); err != nil {
			return nil, err
		}
		labels = append(labels, e.L3VNI)
		communities = append(communities, gobgp.NewRoutersMacExtended(r.RouterMAC.String()))
	}
	if e.Sequence > 0 {
		communities = append(communities, gobgp.NewMacMobilityExtended(e.Sequence, false))
	}
	nlri, err := gobgp.NewEVPNMacIPAdvertisementRoute(rd, gobgp.EthernetSegmentIdentifier{}, e.EthernetTagID, e.MAC.String(), e.IP, labels)
	if err != nil {
		return nil, err
	}
	return &evpnEncoding{nlri: nlri, communities: communities}, nil
}

// encodeIMET builds a Type-3 route with the ingress-replication PMSI
// tunnel whose label is the VNI (RFC 8365 §5.1.3).
func encodeIMET(r *EVPNRouteData, rd gobgp.RouteDistinguisherInterface) (*evpnEncoding, error) {
	e := r.IMET
	if e == nil {
		return nil, ErrInvalidEVPNRoute{RouteType: r.Type, Reason: "the IMET entry is nil"}
	}
	if err := validateVNI(e.VNI); err != nil {
		return nil, err
	}
	if !e.VTEPIP.IsValid() || e.VTEPIP.IsUnspecified() {
		return nil, ErrInvalidIP{IP: e.VTEPIP, Reason: "the IMET entry needs the VTEP address"}
	}
	nlri, err := gobgp.NewEVPNMulticastEthernetTagRoute(rd, e.EthernetTagID, e.originator())
	if err != nil {
		return nil, err
	}
	tunnel, err := gobgp.NewIngressReplTunnelID(e.VTEPIP)
	if err != nil {
		return nil, err
	}
	pmsi := gobgp.NewPathAttributePmsiTunnel(gobgp.PMSI_TUNNEL_TYPE_INGRESS_REPL, false, e.VNI, tunnel)
	return &evpnEncoding{nlri: nlri, attributes: []gobgp.PathAttributeInterface{pmsi}}, nil
}

// encodePrefix builds a Type-5 route: the L3VNI label and, in the
// interface-less model this VTEP originates, the Router's MAC with a zero
// gateway IP (RFC 9136 §4.4.1).
func encodePrefix(r *EVPNRouteData, rd gobgp.RouteDistinguisherInterface) (*evpnEncoding, error) {
	p := r.PrefixData
	if p == nil {
		return nil, ErrInvalidEVPNRoute{RouteType: r.Type, Reason: "the prefix route is nil"}
	}
	if !p.Prefix.IsValid() {
		return nil, ErrPrefixInvalid{Prefix: p.Prefix, Reason: "the Type-5 prefix is invalid"}
	}
	if err := validateVNI(p.VNI); err != nil {
		return nil, err
	}
	var communities []gobgp.ExtendedCommunityInterface
	if !p.GatewayIP.IsValid() || r.RouterMAC != nil {
		if err := validateUnicastMAC(r.RouterMAC); err != nil {
			return nil, err
		}
		communities = append(communities, gobgp.NewRoutersMacExtended(r.RouterMAC.String()))
	}
	prefix := p.Prefix.Masked()
	gateway := p.GatewayIP
	if !gateway.IsValid() {
		gateway = netip.IPv4Unspecified()
		if prefix.Addr().Is6() {
			gateway = netip.IPv6Unspecified()
		}
	}
	if gateway.Is4() != prefix.Addr().Is4() {
		return nil, ErrInvalidIP{IP: gateway, Reason: "the gateway and the prefix are of different families"}
	}
	nlri, err := gobgp.NewEVPNIPPrefixRoute(rd, gobgp.EthernetSegmentIdentifier{}, p.EthernetTagID,
		uint8(prefix.Bits()), prefix.Addr(), gateway, p.VNI)
	if err != nil {
		return nil, err
	}
	return &evpnEncoding{nlri: nlri, communities: communities}, nil
}

// decodeEVPNPath decodes a path GoBGP delivered. A path whose NLRI does not
// parse, or that is not a type the overlay speaks, is an error and is
// dropped. A path whose NLRI parses but whose attributes are unusable is
// returned as a withdrawal together with ErrTreatAsWithdraw (RFC 7606):
// the caller withdraws whatever it holds under that NLRI.
func decodeEVPNPath(p *api.Path) (*EVPNRouteData, error) {
	if p == nil {
		return nil, ErrEntryNil{EntryType: "api.Path"}
	}
	nlri, err := apiutil.GetNativeNlri(p)
	if err != nil {
		return nil, ErrRouteDecodingFailed{Cause: err}
	}
	evpn, ok := nlri.(*gobgp.EVPNNLRI)
	if !ok || evpn == nil {
		return nil, ErrRouteDecodingFailed{Cause: ErrInvalidNLRI{Reason: "not an EVPN NLRI"}}
	}
	route := &EVPNRouteData{Type: EVPNRouteType(evpn.RouteType), IsWithdraw: p.IsWithdraw}
	codec, ok := evpnCodecs[route.Type]
	if !ok {
		return nil, ErrUnsupportedRouteType{RouteType: route.Type}
	}
	if route.RD, err = routeDistinguisherFromNative(evpn.RD()); err != nil {
		return nil, ErrRouteDecodingFailed{RouteType: route.Type, Cause: err}
	}
	if err := codec.decodeNLRI(route, evpn.RouteTypeData); err != nil {
		return nil, ErrRouteDecodingFailed{RouteType: route.Type, Cause: err}
	}
	if route.IsWithdraw {
		return route, nil
	}

	native, err := apiutil.GetNativePathAttributes(p)
	if err != nil {
		return treatAsWithdraw(route, "the path attributes do not parse: "+err.Error())
	}
	attrs := collectEVPNAttributes(native)
	route.NextHop = attrs.nextHop
	route.RouteTargets = attrs.routeTarget
	if reason := validateCommon(attrs); reason != "" {
		return treatAsWithdraw(route, reason)
	}
	if len(attrs.routerMACs) == 1 {
		route.RouterMAC = attrs.routerMACs[0]
	}
	if reason := codec.validate(route, attrs); reason != "" {
		return treatAsWithdraw(route, reason)
	}
	return route, nil
}

// treatAsWithdraw turns route into a withdrawal of its NLRI.
func treatAsWithdraw(route *EVPNRouteData, reason string) (*EVPNRouteData, error) {
	route.IsWithdraw = true
	return route, ErrTreatAsWithdraw{RouteType: route.Type, Reason: reason}
}

// collectEVPNAttributes picks out of the native attributes the ones the
// overlay reads.
func collectEVPNAttributes(native []gobgp.PathAttributeInterface) *evpnAttributes {
	attrs := &evpnAttributes{}
	for _, attr := range native {
		switch a := attr.(type) {
		case *gobgp.PathAttributeMpReachNLRI:
			attrs.nextHop = a.Nexthop
		case *gobgp.PathAttributePmsiTunnel:
			attrs.pmsi = a
		case *gobgp.PathAttributeExtendedCommunities:
			for _, community := range a.Value {
				attrs.addCommunity(community)
			}
		}
	}
	return attrs
}

// addCommunity records one extended community.
func (a *evpnAttributes) addCommunity(community gobgp.ExtendedCommunityInterface) {
	switch c := community.(type) {
	case *gobgp.TwoOctetAsSpecificExtended:
		if c.SubType == gobgp.EC_SUBTYPE_ROUTE_TARGET {
			a.routeTarget = append(a.routeTarget, RouteTarget{AS: c.AS, Value: c.LocalAdmin})
		}
	case *gobgp.EncapExtended:
		if c.TunnelType == gobgp.TUNNEL_TYPE_VXLAN {
			a.vxlan = true
		}
	case *gobgp.RouterMacExtended:
		a.routerMACs = appendDistinctMAC(a.routerMACs, c.Mac)
	case *gobgp.MacMobilityExtended:
		a.sequences = appendDistinctSequence(a.sequences, c.Sequence)
	}
}

// validateCommon checks what every overlay route needs: a VTEP to tunnel
// to, VXLAN encapsulation, and no contradictory communities.
func validateCommon(attrs *evpnAttributes) string {
	switch {
	case !attrs.nextHop.IsValid() || attrs.nextHop.IsUnspecified():
		return "no next hop"
	case !attrs.vxlan:
		return "no VXLAN encapsulation community"
	case len(attrs.routerMACs) > 1:
		return "conflicting Router's MAC communities"
	case len(attrs.routerMACs) == 1 && validateUnicastMAC(attrs.routerMACs[0]) != nil:
		return "the Router's MAC is not a unicast address"
	case len(attrs.sequences) > 1:
		return "conflicting MAC Mobility communities"
	}
	return ""
}

// decodeMACIPNLRI fills a Type-2 route from its NLRI.
func decodeMACIPNLRI(r *EVPNRouteData, data gobgp.EVPNRouteTypeInterface) error {
	route, ok := data.(*gobgp.EVPNMacIPAdvertisementRoute)
	if !ok || route == nil {
		return ErrInvalidNLRI{Reason: "not a MAC/IP Advertisement route"}
	}
	entry := &MACIPEntry{MAC: cloneMAC(route.MacAddress), EthernetTagID: route.ETag}
	if route.IPAddressLength > 0 {
		entry.IP = route.IPAddress
	}
	if len(route.Labels) > 0 {
		entry.VNI = route.Labels[0]
	}
	if len(route.Labels) > 1 {
		entry.L3VNI = route.Labels[1]
	}
	r.MACIP = entry
	return nil
}

// validateMACIP checks a received Type-2 route.
func validateMACIP(r *EVPNRouteData, attrs *evpnAttributes) string {
	e := r.MACIP
	e.VTEPIP = attrs.nextHop
	if len(attrs.sequences) == 1 {
		e.Sequence = attrs.sequences[0]
	}
	if err := validateUnicastMAC(e.MAC); err != nil {
		return err.Error()
	}
	if err := validateVNI(e.VNI); err != nil {
		return "L2VNI label: " + err.Error()
	}
	if e.L3VNI != 0 && r.RouterMAC == nil {
		return "an L3VNI label without the Router's MAC"
	}
	return ""
}

// decodeIMETNLRI fills a Type-3 route from its NLRI. The VNI and the VTEP
// come from the PMSI tunnel attribute, validated with the attributes; a
// withdrawal, which has none, keeps the originator as its VTEP.
func decodeIMETNLRI(r *EVPNRouteData, data gobgp.EVPNRouteTypeInterface) error {
	route, ok := data.(*gobgp.EVPNMulticastEthernetTagRoute)
	if !ok || route == nil {
		return ErrInvalidNLRI{Reason: "not an Inclusive Multicast Ethernet Tag route"}
	}
	r.IMET = &IMETEntry{VTEPIP: route.IPAddress, OriginatorIP: route.IPAddress, EthernetTagID: route.ETag}
	return nil
}

// validateIMET checks a received Type-3 route: it must name an
// ingress-replication tunnel whose label is the VNI.
func validateIMET(r *EVPNRouteData, attrs *evpnAttributes) string {
	pmsi := attrs.pmsi
	if pmsi == nil {
		return "no PMSI tunnel attribute"
	}
	if pmsi.TunnelType != gobgp.PMSI_TUNNEL_TYPE_INGRESS_REPL {
		return "the PMSI tunnel is not ingress replication"
	}
	tunnel, ok := pmsi.TunnelID.(*gobgp.IngressReplTunnelID)
	if !ok || tunnel == nil || !tunnel.Value.IsValid() || tunnel.Value.IsUnspecified() {
		return "the PMSI tunnel names no endpoint"
	}
	if err := validateVNI(pmsi.Label); err != nil {
		return "PMSI label: " + err.Error()
	}
	r.IMET.VNI = pmsi.Label
	r.IMET.VTEPIP = tunnel.Value
	return ""
}

// decodePrefixNLRI fills a Type-5 route from its NLRI.
func decodePrefixNLRI(r *EVPNRouteData, data gobgp.EVPNRouteTypeInterface) error {
	route, ok := data.(*gobgp.EVPNIPPrefixRoute)
	if !ok || route == nil {
		return ErrInvalidNLRI{Reason: "not an IP Prefix route"}
	}
	prefix, err := route.IPPrefix.Prefix(int(route.IPPrefixLength))
	if err != nil {
		return ErrInvalidNLRI{Reason: "prefix length " + strconv.Itoa(int(route.IPPrefixLength)) + " does not fit the address"}
	}
	entry := &PrefixRoute{Prefix: prefix, VNI: route.Label, EthernetTagID: route.ETag}
	if route.GWIPAddress.IsValid() && !route.GWIPAddress.IsUnspecified() {
		entry.GatewayIP = route.GWIPAddress
	}
	r.PrefixData = entry
	return nil
}

// validatePrefix checks a received Type-5 route. In the interface-less
// model the Router's MAC is the only way to reach the VTEP's IP-VRF.
func validatePrefix(r *EVPNRouteData, attrs *evpnAttributes) string {
	p := r.PrefixData
	p.VTEPIP = attrs.nextHop
	if err := validateVNI(p.VNI); err != nil {
		return "L3VNI label: " + err.Error()
	}
	if !p.GatewayIP.IsValid() && r.RouterMAC == nil {
		return "an interface-less prefix route without the Router's MAC"
	}
	return ""
}

// validateUnicastMAC checks a host or router MAC: six bytes, not a group
// address.
func validateUnicastMAC(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return ErrInvalidMAC{MAC: mac, Reason: "must be 6 bytes"}
	}
	if mac[0]&0x01 != 0 {
		return ErrInvalidMAC{MAC: mac, Reason: "a group address is not a host"}
	}
	return nil
}

// cloneMAC copies a hardware address.
func cloneMAC(mac net.HardwareAddr) net.HardwareAddr {
	if mac == nil {
		return nil
	}
	return append(net.HardwareAddr(nil), mac...)
}

// appendDistinctMAC appends mac unless it is already present.
func appendDistinctMAC(macs []net.HardwareAddr, mac net.HardwareAddr) []net.HardwareAddr {
	for _, seen := range macs {
		if string(seen) == string(mac) {
			return macs
		}
	}
	return append(macs, cloneMAC(mac))
}

// appendDistinctSequence appends seq unless it is already present.
func appendDistinctSequence(seqs []uint32, seq uint32) []uint32 {
	for _, seen := range seqs {
		if seen == seq {
			return seqs
		}
	}
	return append(seqs, seq)
}

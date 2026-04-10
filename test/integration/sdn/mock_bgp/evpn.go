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

//go:build integration

package mock_bgp

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// EVPNRouteBuilder helps construct EVPN routes for injection.
type EVPNRouteBuilder struct {
	routeType EVPNRouteType
	data      *EVPNRouteData
	nextHop   netip.Addr
	asPath    []uint32
	origin    uint8
}

// NewType2RouteBuilder creates a builder for Type-2 MAC/IP routes.
func NewType2RouteBuilder() *EVPNRouteBuilder {
	return &EVPNRouteBuilder{
		routeType: EVPNTypeMACIP,
		data: &EVPNRouteData{
			Type: EVPNTypeMACIP,
		},
	}
}

// NewType3RouteBuilder creates a builder for Type-3 Inclusive Multicast routes.
func NewType3RouteBuilder() *EVPNRouteBuilder {
	return &EVPNRouteBuilder{
		routeType: EVPNTypeMulticast,
		data: &EVPNRouteData{
			Type: EVPNTypeMulticast,
		},
	}
}

// NewType5RouteBuilder creates a builder for Type-5 IP Prefix routes.
func NewType5RouteBuilder() *EVPNRouteBuilder {
	return &EVPNRouteBuilder{
		routeType: EVPNTypeIPPrefix,
		data: &EVPNRouteData{
			Type: EVPNTypeIPPrefix,
		},
	}
}

// WithRouteDistinguisher sets the route distinguisher.
func (b *EVPNRouteBuilder) WithRouteDistinguisher(rd string) *EVPNRouteBuilder {
	b.data.RouteDistinguisher = rd
	return b
}

// WithEthernetTag sets the Ethernet tag ID.
func (b *EVPNRouteBuilder) WithEthernetTag(tag uint32) *EVPNRouteBuilder {
	b.data.EthernetTag = tag
	return b
}

// WithMAC sets the MAC address for Type-2 routes.
func (b *EVPNRouteBuilder) WithMAC(mac string) *EVPNRouteBuilder {
	hwAddr, _ := net.ParseMAC(mac)
	b.data.MAC = hwAddr
	return b
}

// WithMACBytes sets the MAC address from bytes for Type-2 routes.
func (b *EVPNRouteBuilder) WithMACBytes(mac net.HardwareAddr) *EVPNRouteBuilder {
	b.data.MAC = mac
	return b
}

// WithIP sets the IP address for Type-2 routes.
func (b *EVPNRouteBuilder) WithIP(ip string) *EVPNRouteBuilder {
	addr, _ := netip.ParseAddr(ip)
	b.data.IP = addr
	return b
}

// WithIPAddr sets the IP address from netip.Addr for Type-2 routes.
func (b *EVPNRouteBuilder) WithIPAddr(ip netip.Addr) *EVPNRouteBuilder {
	b.data.IP = ip
	return b
}

// WithOriginatingIP sets the originating router IP for Type-3 routes.
func (b *EVPNRouteBuilder) WithOriginatingIP(ip string) *EVPNRouteBuilder {
	addr, _ := netip.ParseAddr(ip)
	b.data.OriginatingIP = addr
	return b
}

// WithOriginatingIPAddr sets the originating router IP from netip.Addr for Type-3 routes.
func (b *EVPNRouteBuilder) WithOriginatingIPAddr(ip netip.Addr) *EVPNRouteBuilder {
	b.data.OriginatingIP = ip
	return b
}

// WithPrefix sets the IP prefix for Type-5 routes.
func (b *EVPNRouteBuilder) WithPrefix(prefix string) *EVPNRouteBuilder {
	p, _ := netip.ParsePrefix(prefix)
	b.data.IPPrefix = p
	return b
}

// WithPrefixAddr sets the IP prefix from netip.Prefix for Type-5 routes.
func (b *EVPNRouteBuilder) WithPrefixAddr(prefix netip.Prefix) *EVPNRouteBuilder {
	b.data.IPPrefix = prefix
	return b
}

// WithGatewayIP sets the gateway IP for Type-5 routes.
func (b *EVPNRouteBuilder) WithGatewayIP(ip string) *EVPNRouteBuilder {
	addr, _ := netip.ParseAddr(ip)
	b.data.GatewayIP = addr
	return b
}

// WithGatewayIPAddr sets the gateway IP from netip.Addr for Type-5 routes.
func (b *EVPNRouteBuilder) WithGatewayIPAddr(ip netip.Addr) *EVPNRouteBuilder {
	b.data.GatewayIP = ip
	return b
}

// WithVNI sets the VXLAN Network Identifier.
func (b *EVPNRouteBuilder) WithVNI(vni uint32) *EVPNRouteBuilder {
	b.data.VNI = vni
	b.data.Labels = []uint32{vni}
	return b
}

// WithRouteTargets sets the route targets.
func (b *EVPNRouteBuilder) WithRouteTargets(rts ...string) *EVPNRouteBuilder {
	b.data.RouteTargets = rts
	return b
}

// WithNextHop sets the BGP next-hop address.
func (b *EVPNRouteBuilder) WithNextHop(nh string) *EVPNRouteBuilder {
	addr, _ := netip.ParseAddr(nh)
	b.nextHop = addr
	return b
}

// WithNextHopAddr sets the BGP next-hop address from netip.Addr.
func (b *EVPNRouteBuilder) WithNextHopAddr(nh netip.Addr) *EVPNRouteBuilder {
	b.nextHop = nh
	return b
}

// WithASPath sets the AS path.
func (b *EVPNRouteBuilder) WithASPath(asPath ...uint32) *EVPNRouteBuilder {
	b.asPath = asPath
	return b
}

// WithOrigin sets the origin attribute (0=IGP, 1=EGP, 2=Incomplete).
func (b *EVPNRouteBuilder) WithOrigin(origin uint8) *EVPNRouteBuilder {
	b.origin = origin
	return b
}

// Build creates the RouteInjection for the EVPN route.
func (b *EVPNRouteBuilder) Build() *RouteInjection {
	return &RouteInjection{
		Family:    AFamilyEVPN,
		NextHop:   b.nextHop,
		ASPath:    b.asPath,
		Origin:    b.origin,
		EVPNRoute: b.data,
	}
}

// EVPNRouteStore provides specialized storage for EVPN routes.
type EVPNRouteStore struct {
	// Type-2: MAC/IP routes (key: VNI:MAC or VNI:MAC:IP)
	macIPRoutes map[string]*ReceivedRoute

	// Type-3: Multicast routes (key: VNI:VTEP)
	multicastRoutes map[string]*ReceivedRoute

	// Type-5: IP Prefix routes (key: VNI:Prefix)
	prefixRoutes map[string]*ReceivedRoute
}

// NewEVPNRouteStore creates a new EVPN route store.
func NewEVPNRouteStore() *EVPNRouteStore {
	return &EVPNRouteStore{
		macIPRoutes:     make(map[string]*ReceivedRoute),
		multicastRoutes: make(map[string]*ReceivedRoute),
		prefixRoutes:    make(map[string]*ReceivedRoute),
	}
}

// AddRoute adds an EVPN route to the store.
func (s *EVPNRouteStore) AddRoute(route *ReceivedRoute) {
	if route == nil || route.EVPNRoute == nil {
		return
	}

	switch route.EVPNRoute.Type {
	case EVPNTypeMACIP:
		key := s.macIPKey(route.EVPNRoute)
		s.macIPRoutes[key] = route
	case EVPNTypeMulticast:
		key := s.multicastKey(route.EVPNRoute)
		s.multicastRoutes[key] = route
	case EVPNTypeIPPrefix:
		key := s.prefixKey(route.EVPNRoute)
		s.prefixRoutes[key] = route
	}
}

// RemoveRoute removes an EVPN route from the store.
func (s *EVPNRouteStore) RemoveRoute(route *ReceivedRoute) {
	if route == nil || route.EVPNRoute == nil {
		return
	}

	switch route.EVPNRoute.Type {
	case EVPNTypeMACIP:
		key := s.macIPKey(route.EVPNRoute)
		delete(s.macIPRoutes, key)
	case EVPNTypeMulticast:
		key := s.multicastKey(route.EVPNRoute)
		delete(s.multicastRoutes, key)
	case EVPNTypeIPPrefix:
		key := s.prefixKey(route.EVPNRoute)
		delete(s.prefixRoutes, key)
	}
}

// GetMACIPRoute retrieves a Type-2 MAC/IP route.
func (s *EVPNRouteStore) GetMACIPRoute(vni uint32, mac net.HardwareAddr, ip netip.Addr) (*ReceivedRoute, bool) {
	key := formatVNIMACIP(vni, mac, ip)
	route, ok := s.macIPRoutes[key]
	return route, ok
}

// GetMulticastRoute retrieves a Type-3 multicast route.
func (s *EVPNRouteStore) GetMulticastRoute(vni uint32, vtep netip.Addr) (*ReceivedRoute, bool) {
	key := formatVNIVTEP(vni, vtep)
	route, ok := s.multicastRoutes[key]
	return route, ok
}

// GetPrefixRoute retrieves a Type-5 prefix route.
func (s *EVPNRouteStore) GetPrefixRoute(vni uint32, prefix netip.Prefix) (*ReceivedRoute, bool) {
	key := formatVNIPrefix(vni, prefix)
	route, ok := s.prefixRoutes[key]
	return route, ok
}

// GetAllMACIPRoutes returns all Type-2 routes.
func (s *EVPNRouteStore) GetAllMACIPRoutes() []*ReceivedRoute {
	routes := make([]*ReceivedRoute, 0, len(s.macIPRoutes))
	for _, route := range s.macIPRoutes {
		routes = append(routes, route)
	}
	return routes
}

// GetAllMulticastRoutes returns all Type-3 routes.
func (s *EVPNRouteStore) GetAllMulticastRoutes() []*ReceivedRoute {
	routes := make([]*ReceivedRoute, 0, len(s.multicastRoutes))
	for _, route := range s.multicastRoutes {
		routes = append(routes, route)
	}
	return routes
}

// GetAllPrefixRoutes returns all Type-5 routes.
func (s *EVPNRouteStore) GetAllPrefixRoutes() []*ReceivedRoute {
	routes := make([]*ReceivedRoute, 0, len(s.prefixRoutes))
	for _, route := range s.prefixRoutes {
		routes = append(routes, route)
	}
	return routes
}

// GetMACIPRoutesByVNI returns all Type-2 routes for a specific VNI.
func (s *EVPNRouteStore) GetMACIPRoutesByVNI(vni uint32) []*ReceivedRoute {
	routes := make([]*ReceivedRoute, 0)
	vniPrefix := uint32ToStr(vni) + ":"
	for key, route := range s.macIPRoutes {
		if hasPrefix(key, vniPrefix) {
			routes = append(routes, route)
		}
	}
	return routes
}

// GetMulticastRoutesByVNI returns all Type-3 routes for a specific VNI.
func (s *EVPNRouteStore) GetMulticastRoutesByVNI(vni uint32) []*ReceivedRoute {
	routes := make([]*ReceivedRoute, 0)
	vniPrefix := uint32ToStr(vni) + ":"
	for key, route := range s.multicastRoutes {
		if hasPrefix(key, vniPrefix) {
			routes = append(routes, route)
		}
	}
	return routes
}

// GetPrefixRoutesByVNI returns all Type-5 routes for a specific VNI.
func (s *EVPNRouteStore) GetPrefixRoutesByVNI(vni uint32) []*ReceivedRoute {
	routes := make([]*ReceivedRoute, 0)
	vniPrefix := uint32ToStr(vni) + ":"
	for key, route := range s.prefixRoutes {
		if hasPrefix(key, vniPrefix) {
			routes = append(routes, route)
		}
	}
	return routes
}

// CountByType returns the count of routes by type.
func (s *EVPNRouteStore) CountByType(routeType EVPNRouteType) int {
	switch routeType {
	case EVPNTypeMACIP:
		return len(s.macIPRoutes)
	case EVPNTypeMulticast:
		return len(s.multicastRoutes)
	case EVPNTypeIPPrefix:
		return len(s.prefixRoutes)
	default:
		return 0
	}
}

// TotalCount returns the total number of EVPN routes.
func (s *EVPNRouteStore) TotalCount() int {
	return len(s.macIPRoutes) + len(s.multicastRoutes) + len(s.prefixRoutes)
}

// Clear removes all routes from the store.
func (s *EVPNRouteStore) Clear() {
	s.macIPRoutes = make(map[string]*ReceivedRoute)
	s.multicastRoutes = make(map[string]*ReceivedRoute)
	s.prefixRoutes = make(map[string]*ReceivedRoute)
}

// macIPKey generates a key for MAC/IP routes.
func (s *EVPNRouteStore) macIPKey(data *EVPNRouteData) string {
	return formatVNIMACIP(data.VNI, data.MAC, data.IP)
}

// multicastKey generates a key for multicast routes.
func (s *EVPNRouteStore) multicastKey(data *EVPNRouteData) string {
	return formatVNIVTEP(data.VNI, data.OriginatingIP)
}

// prefixKey generates a key for prefix routes.
func (s *EVPNRouteStore) prefixKey(data *EVPNRouteData) string {
	return formatVNIPrefix(data.VNI, data.IPPrefix)
}

// Helper functions for key formatting

func formatVNIMACIP(vni uint32, mac net.HardwareAddr, ip netip.Addr) string {
	key := uint32ToStr(vni) + ":" + mac.String()
	if ip.IsValid() {
		key += ":" + ip.String()
	}
	return key
}

func formatVNIVTEP(vni uint32, vtep netip.Addr) string {
	return uint32ToStr(vni) + ":" + vtep.String()
}

func formatVNIPrefix(vni uint32, prefix netip.Prefix) string {
	return uint32ToStr(vni) + ":" + prefix.String()
}

func uint32ToStr(n uint32) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 10)
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n%10) + '0'
		n /= 10
	}
	return string(buf[i:])
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// ParseEVPNNLRI parses raw EVPN NLRI bytes into EVPNRouteData.
func ParseEVPNNLRI(nlri []byte) (*EVPNRouteData, error) {
	if len(nlri) < 2 {
		return nil, ErrInvalidConfig
	}

	routeType := EVPNRouteType(nlri[0])
	length := int(nlri[1])

	if len(nlri) < length+2 {
		return nil, ErrInvalidConfig
	}

	data := &EVPNRouteData{
		Type: routeType,
	}

	switch routeType {
	case EVPNTypeMACIP:
		return parseType2NLRI(nlri[2:], data)
	case EVPNTypeMulticast:
		return parseType3NLRI(nlri[2:], data)
	case EVPNTypeIPPrefix:
		return parseType5NLRI(nlri[2:], data)
	default:
		return nil, ErrInvalidConfig
	}
}

// parseType2NLRI parses Type-2 MAC/IP Advertisement NLRI.
func parseType2NLRI(data []byte, route *EVPNRouteData) (*EVPNRouteData, error) {
	if len(data) < 25 {
		return nil, ErrInvalidConfig
	}

	offset := 0

	// Route Distinguisher (8 bytes)
	route.RouteDistinguisher = formatRD(data[offset : offset+8])
	offset += 8

	// Ethernet Tag (4 bytes)
	route.EthernetTag = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// MAC Address Length (1 byte) - should be 48
	macLen := int(data[offset])
	offset++
	if macLen != 48 {
		return nil, ErrInvalidConfig
	}

	// MAC Address (6 bytes)
	route.MAC = make(net.HardwareAddr, 6)
	copy(route.MAC, data[offset:offset+6])
	offset += 6

	// IP Address Length (1 byte)
	ipLen := int(data[offset])
	offset++

	// IP Address (0, 4, or 16 bytes)
	if ipLen == 32 {
		route.IP = netip.AddrFrom4([4]byte{
			data[offset], data[offset+1], data[offset+2], data[offset+3],
		})
		offset += 4
	} else if ipLen == 128 {
		var ipBytes [16]byte
		copy(ipBytes[:], data[offset:offset+16])
		route.IP = netip.AddrFrom16(ipBytes)
		offset += 16
	}

	// MPLS Label (3 bytes) -> VNI
	if offset+3 <= len(data) {
		label := uint32(data[offset])<<16 | uint32(data[offset+1])<<8 | uint32(data[offset+2])
		route.VNI = label >> 4
		route.Labels = []uint32{route.VNI}
	}

	return route, nil
}

// parseType3NLRI parses Type-3 Inclusive Multicast NLRI.
func parseType3NLRI(data []byte, route *EVPNRouteData) (*EVPNRouteData, error) {
	if len(data) < 13 {
		return nil, ErrInvalidConfig
	}

	offset := 0

	// Route Distinguisher (8 bytes)
	route.RouteDistinguisher = formatRD(data[offset : offset+8])
	offset += 8

	// Ethernet Tag (4 bytes)
	route.EthernetTag = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// IP Address Length (1 byte)
	ipLen := int(data[offset])
	offset++

	// Originating Router IP
	if ipLen == 32 {
		route.OriginatingIP = netip.AddrFrom4([4]byte{
			data[offset], data[offset+1], data[offset+2], data[offset+3],
		})
	} else if ipLen == 128 {
		var ipBytes [16]byte
		copy(ipBytes[:], data[offset:offset+16])
		route.OriginatingIP = netip.AddrFrom16(ipBytes)
	}

	return route, nil
}

// parseType5NLRI parses Type-5 IP Prefix NLRI.
// The format matches BuildType5NLRI: RD(8) + ESI(10) + ETag(4) + PrefixLen(1) + Prefix(var) + GW(var) + Label(3)
func parseType5NLRI(data []byte, route *EVPNRouteData) (*EVPNRouteData, error) {
	if len(data) < 22 {
		return nil, ErrInvalidConfig
	}

	offset := 0

	// Route Distinguisher (8 bytes)
	route.RouteDistinguisher = formatRD(data[offset : offset+8])
	offset += 8

	// ESI (10 bytes) - skip
	offset += 10

	// Ethernet Tag (4 bytes)
	route.EthernetTag = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// IP Prefix Length (1 byte)
	prefixLen := int(data[offset])
	offset++

	// IP Prefix - uses variable length bytes based on prefix length
	prefixBytes := (prefixLen + 7) / 8
	isIPv4 := prefixLen <= 32

	if isIPv4 {
		var ipBytes [4]byte
		copy(ipBytes[:], data[offset:offset+prefixBytes])
		addr := netip.AddrFrom4(ipBytes)
		route.IPPrefix = netip.PrefixFrom(addr, prefixLen)
		offset += prefixBytes

		// Gateway IP (4 bytes for IPv4)
		if offset+4 <= len(data) {
			route.GatewayIP = netip.AddrFrom4([4]byte{
				data[offset], data[offset+1], data[offset+2], data[offset+3],
			})
			offset += 4
		}
	} else {
		var ipBytes [16]byte
		copy(ipBytes[:], data[offset:offset+prefixBytes])
		addr := netip.AddrFrom16(ipBytes)
		route.IPPrefix = netip.PrefixFrom(addr, prefixLen)
		offset += prefixBytes

		// Gateway IP (16 bytes for IPv6)
		if offset+16 <= len(data) {
			var gwBytes [16]byte
			copy(gwBytes[:], data[offset:offset+16])
			route.GatewayIP = netip.AddrFrom16(gwBytes)
			offset += 16
		}
	}

	// MPLS Label (3 bytes) -> VNI
	if offset+3 <= len(data) {
		label := uint32(data[offset])<<16 | uint32(data[offset+1])<<8 | uint32(data[offset+2])
		route.VNI = label >> 4
	}

	return route, nil
}

// formatRD formats an 8-byte Route Distinguisher as a string.
func formatRD(rd []byte) string {
	if len(rd) < 8 {
		return ""
	}

	rdType := binary.BigEndian.Uint16(rd[0:2])

	switch rdType {
	case 0:
		admin := binary.BigEndian.Uint16(rd[2:4])
		assigned := binary.BigEndian.Uint32(rd[4:8])
		return uint32ToStr(uint32(admin)) + ":" + uint32ToStr(assigned)
	case 1:
		admin := netip.AddrFrom4([4]byte{rd[2], rd[3], rd[4], rd[5]})
		assigned := binary.BigEndian.Uint16(rd[6:8])
		return admin.String() + ":" + uint32ToStr(uint32(assigned))
	case 2:
		admin := binary.BigEndian.Uint32(rd[2:6])
		assigned := binary.BigEndian.Uint16(rd[6:8])
		return uint32ToStr(admin) + ":" + uint32ToStr(uint32(assigned))
	default:
		return ""
	}
}

// BuildType2NLRI builds raw NLRI bytes for a Type-2 MAC/IP route.
func BuildType2NLRI(vni uint32, mac net.HardwareAddr, ip netip.Addr, rdAdmin uint32, rdAssigned uint32) []byte {
	ipLen := 0
	var ipBytes []byte
	if ip.IsValid() {
		ipBytes = ip.AsSlice()
		if ip.Is4() {
			ipLen = 32
		} else {
			ipLen = 128
		}
	}

	nlriLen := 8 + 4 + 1 + 6 + 1 + len(ipBytes) + 3
	nlri := make([]byte, nlriLen+2)

	nlri[0] = byte(EVPNTypeMACIP)
	nlri[1] = byte(nlriLen)

	offset := 2

	// Route Distinguisher (Type 0)
	binary.BigEndian.PutUint16(nlri[offset:], 0)
	binary.BigEndian.PutUint16(nlri[offset+2:], uint16(rdAdmin))
	binary.BigEndian.PutUint32(nlri[offset+4:], rdAssigned)
	offset += 8

	// Ethernet Tag
	binary.BigEndian.PutUint32(nlri[offset:], 0)
	offset += 4

	// MAC Length
	nlri[offset] = 48
	offset++

	// MAC Address
	copy(nlri[offset:], mac)
	offset += 6

	// IP Length
	nlri[offset] = byte(ipLen)
	offset++

	// IP Address
	if len(ipBytes) > 0 {
		copy(nlri[offset:], ipBytes)
		offset += len(ipBytes)
	}

	// MPLS Label (VNI)
	label := (vni << 4) | 0x01
	nlri[offset] = byte(label >> 16)
	nlri[offset+1] = byte(label >> 8)
	nlri[offset+2] = byte(label)

	return nlri
}

// BuildType3NLRI builds raw NLRI bytes for a Type-3 Inclusive Multicast route.
func BuildType3NLRI(vni uint32, vtepIP netip.Addr, rdAdmin uint32, rdAssigned uint32) []byte {
	ipBytes := vtepIP.AsSlice()
	ipLen := 32
	if vtepIP.Is6() {
		ipLen = 128
	}

	nlriLen := 8 + 4 + 1 + len(ipBytes)
	nlri := make([]byte, nlriLen+2)

	nlri[0] = byte(EVPNTypeMulticast)
	nlri[1] = byte(nlriLen)

	offset := 2

	// Route Distinguisher (Type 0)
	binary.BigEndian.PutUint16(nlri[offset:], 0)
	binary.BigEndian.PutUint16(nlri[offset+2:], uint16(rdAdmin))
	binary.BigEndian.PutUint32(nlri[offset+4:], rdAssigned)
	offset += 8

	// Ethernet Tag
	binary.BigEndian.PutUint32(nlri[offset:], 0)
	offset += 4

	// IP Length
	nlri[offset] = byte(ipLen)
	offset++

	// Originating Router IP
	copy(nlri[offset:], ipBytes)

	return nlri
}

// BuildType5NLRI builds raw NLRI bytes for a Type-5 IP Prefix route.
func BuildType5NLRI(vni uint32, prefix netip.Prefix, gatewayIP netip.Addr, rdAdmin uint32, rdAssigned uint32) []byte {
	prefixBits := prefix.Bits()
	prefixBytes := (prefixBits + 7) / 8
	prefixIP := prefix.Addr().AsSlice()

	gwLen := 4
	var gwIP []byte
	if gatewayIP.IsValid() {
		gwIP = gatewayIP.AsSlice()
		gwLen = len(gwIP)
	} else {
		gwIP = make([]byte, 4)
	}

	nlriLen := 8 + 10 + 4 + 1 + prefixBytes + gwLen + 3
	nlri := make([]byte, nlriLen+2)

	nlri[0] = byte(EVPNTypeIPPrefix)
	nlri[1] = byte(nlriLen)

	offset := 2

	// Route Distinguisher (Type 0)
	binary.BigEndian.PutUint16(nlri[offset:], 0)
	binary.BigEndian.PutUint16(nlri[offset+2:], uint16(rdAdmin))
	binary.BigEndian.PutUint32(nlri[offset+4:], rdAssigned)
	offset += 8

	// ESI (all zeros)
	offset += 10

	// Ethernet Tag
	binary.BigEndian.PutUint32(nlri[offset:], 0)
	offset += 4

	// IP Prefix Length
	nlri[offset] = byte(prefixBits)
	offset++

	// IP Prefix
	copy(nlri[offset:], prefixIP[:prefixBytes])
	offset += prefixBytes

	// Gateway IP
	copy(nlri[offset:], gwIP)
	offset += gwLen

	// MPLS Label (VNI)
	label := (vni << 4) | 0x01
	nlri[offset] = byte(label >> 16)
	nlri[offset+1] = byte(label >> 8)
	nlri[offset+2] = byte(label)

	return nlri
}

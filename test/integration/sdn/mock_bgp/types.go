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

// Package mock_bgp provides mock BGP peers for integration testing of the SDN BGP service.
// It uses the GoBGP library to simulate external BGP peers that can establish sessions,
// receive route announcements, and inject routes for testing purposes.
package mock_bgp

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// MockBGPPeerConfig holds configuration for creating a mock BGP peer.
type MockBGPPeerConfig struct {
	// ASN is the Autonomous System Number for this mock peer.
	ASN uint32

	// RouterID is the BGP router identifier.
	RouterID string

	// ListenAddr is the address to listen on for incoming BGP connections.
	// Format: "ip:port" or ":port" for all interfaces.
	ListenAddr string

	// Neighbors are the BGP neighbors this peer should connect to or accept.
	Neighbors []MockNeighborConfig

	// EnabledFamilies specifies which address families to enable.
	// Defaults to IPv4 unicast if empty.
	EnabledFamilies []AddressFamily

	// PassiveMode if true, the peer will only accept incoming connections.
	PassiveMode bool

	// GracefulRestartEnabled enables graceful restart capability.
	GracefulRestartEnabled bool

	// GracefulRestartTime is the restart time in seconds.
	GracefulRestartTime uint16
}

// MockNeighborConfig holds configuration for a mock BGP neighbor.
type MockNeighborConfig struct {
	// Address is the IP address of the neighbor.
	Address string

	// ASN is the AS number of the neighbor.
	ASN uint32

	// HoldTime is the BGP hold timer in seconds. Defaults to 90.
	HoldTime uint16

	// KeepaliveInterval is the keepalive interval in seconds. Defaults to 30.
	KeepaliveInterval uint16

	// PassiveMode if true, only accept connections from this neighbor.
	PassiveMode bool

	// EnabledFamilies specifies which address families to enable for this neighbor.
	EnabledFamilies []AddressFamily
}

// AddressFamily specifies the BGP address family.
type AddressFamily uint8

const (
	// AFamilyIPv4Unicast represents IPv4 unicast routes.
	AFamilyIPv4Unicast AddressFamily = iota

	// AFamilyIPv6Unicast represents IPv6 unicast routes.
	AFamilyIPv6Unicast

	// AFamilyEVPN represents Ethernet VPN routes for VXLAN.
	AFamilyEVPN
)

// String returns the string representation of the address family.
func (af AddressFamily) String() string {
	switch af {
	case AFamilyIPv4Unicast:
		return "ipv4-unicast"
	case AFamilyIPv6Unicast:
		return "ipv6-unicast"
	case AFamilyEVPN:
		return "l2vpn-evpn"
	default:
		return "unknown"
	}
}

// ReceivedRoute represents a route received from a BGP peer.
type ReceivedRoute struct {
	// Family is the address family of the route.
	Family AddressFamily

	// Prefix is the IP prefix for unicast routes.
	Prefix netip.Prefix

	// NextHop is the BGP next-hop address.
	NextHop netip.Addr

	// ASPath is the AS path attribute.
	ASPath []uint32

	// LocalPref is the LOCAL_PREF attribute.
	LocalPref uint32

	// MED is the Multi-Exit Discriminator.
	MED uint32

	// Communities are standard BGP communities.
	Communities []uint32

	// ExtendedCommunities are extended BGP communities.
	ExtendedCommunities []string

	// LargeCommunities are large BGP communities.
	LargeCommunities []string

	// Origin is the origin attribute (IGP, EGP, Incomplete).
	Origin uint8

	// ReceivedAt is when this route was received.
	ReceivedAt time.Time

	// PeerAddress is the address of the peer that sent this route.
	PeerAddress netip.Addr

	// IsWithdraw indicates if this is a route withdrawal.
	IsWithdraw bool

	// EVPNRoute holds EVPN-specific route data.
	EVPNRoute *EVPNRouteData
}

// EVPNRouteData holds EVPN-specific route information.
type EVPNRouteData struct {
	// Type is the EVPN route type (2, 3, or 5).
	Type EVPNRouteType

	// RouteDistinguisher is the RD for the route.
	RouteDistinguisher string

	// EthernetTag is the Ethernet Tag ID.
	EthernetTag uint32

	// MAC is the MAC address for Type-2 routes.
	MAC net.HardwareAddr

	// IP is the IP address for Type-2 routes (optional).
	IP netip.Addr

	// OriginatingIP is the originating router IP for Type-3 routes.
	OriginatingIP netip.Addr

	// IPPrefix is the IP prefix for Type-5 routes.
	IPPrefix netip.Prefix

	// GatewayIP is the gateway IP for Type-5 routes.
	GatewayIP netip.Addr

	// VNI is the VXLAN Network Identifier.
	VNI uint32

	// RouteTargets are the route targets.
	RouteTargets []string

	// Labels are MPLS labels (VNI in VXLAN context).
	Labels []uint32
}

// EVPNRouteType specifies the type of EVPN route.
type EVPNRouteType uint8

const (
	// EVPNTypeMACIP is Type-2 MAC/IP Advertisement.
	EVPNTypeMACIP EVPNRouteType = 2

	// EVPNTypeMulticast is Type-3 Inclusive Multicast.
	EVPNTypeMulticast EVPNRouteType = 3

	// EVPNTypeIPPrefix is Type-5 IP Prefix.
	EVPNTypeIPPrefix EVPNRouteType = 5
)

// String returns the string representation of the EVPN route type.
func (t EVPNRouteType) String() string {
	switch t {
	case EVPNTypeMACIP:
		return "type-2-mac-ip"
	case EVPNTypeMulticast:
		return "type-3-multicast"
	case EVPNTypeIPPrefix:
		return "type-5-prefix"
	default:
		return "unknown"
	}
}

// PeerState represents the state of a BGP peer session.
type PeerState uint8

const (
	// PeerStateIdle indicates the peer is idle.
	PeerStateIdle PeerState = iota

	// PeerStateConnect indicates the peer is attempting to connect.
	PeerStateConnect

	// PeerStateActive indicates the peer is actively trying to establish.
	PeerStateActive

	// PeerStateOpenSent indicates OPEN message has been sent.
	PeerStateOpenSent

	// PeerStateOpenConfirm indicates waiting for KEEPALIVE.
	PeerStateOpenConfirm

	// PeerStateEstablished indicates the session is established.
	PeerStateEstablished
)

// String returns the string representation of the peer state.
func (s PeerState) String() string {
	switch s {
	case PeerStateIdle:
		return "Idle"
	case PeerStateConnect:
		return "Connect"
	case PeerStateActive:
		return "Active"
	case PeerStateOpenSent:
		return "OpenSent"
	case PeerStateOpenConfirm:
		return "OpenConfirm"
	case PeerStateEstablished:
		return "Established"
	default:
		return "Unknown"
	}
}

// IsUp returns true if the peer is established.
func (s PeerState) IsUp() bool {
	return s == PeerStateEstablished
}

// NeighborState holds the current state of a neighbor.
type NeighborState struct {
	// Address is the neighbor's IP address.
	Address netip.Addr

	// ASN is the neighbor's AS number.
	ASN uint32

	// State is the current session state.
	State PeerState

	// Uptime is the duration since the session was established.
	Uptime time.Duration

	// RoutesReceived is the number of routes received from this neighbor.
	RoutesReceived int64

	// RoutesSent is the number of routes sent to this neighbor.
	RoutesSent int64

	// LastStateChange is when the state last changed.
	LastStateChange time.Time
}

// RouteInjection represents a route to be injected (announced) to peers.
type RouteInjection struct {
	// Family is the address family of the route.
	Family AddressFamily

	// Prefix is the IP prefix for unicast routes.
	Prefix netip.Prefix

	// NextHop is the BGP next-hop address.
	NextHop netip.Addr

	// ASPath is the AS path to announce.
	ASPath []uint32

	// LocalPref is the LOCAL_PREF attribute.
	LocalPref uint32

	// MED is the Multi-Exit Discriminator.
	MED uint32

	// Communities are standard BGP communities.
	Communities []uint32

	// Origin is the origin attribute (0=IGP, 1=EGP, 2=Incomplete).
	Origin uint8

	// EVPNRoute holds EVPN-specific route data for injection.
	EVPNRoute *EVPNRouteData
}

// RouteStore provides thread-safe storage for received routes.
type RouteStore struct {
	mu     sync.RWMutex
	routes map[string]*ReceivedRoute
	// routeHistory stores all route events for analysis
	routeHistory []RouteEvent
}

// RouteEvent records a route advertisement or withdrawal event.
type RouteEvent struct {
	// Route is the route that was received or withdrawn.
	Route *ReceivedRoute

	// Timestamp is when this event occurred.
	Timestamp time.Time

	// IsWithdraw indicates if this was a withdrawal.
	IsWithdraw bool
}

// NewRouteStore creates a new route store.
func NewRouteStore() *RouteStore {
	return &RouteStore{
		routes:       make(map[string]*ReceivedRoute),
		routeHistory: make([]RouteEvent, 0),
	}
}

// Add adds or updates a route in the store.
func (s *RouteStore) Add(route *ReceivedRoute) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.routeKey(route)
	s.routes[key] = route
	s.routeHistory = append(s.routeHistory, RouteEvent{
		Route:      route,
		Timestamp:  time.Now(),
		IsWithdraw: false,
	})
}

// Remove removes a route from the store.
func (s *RouteStore) Remove(route *ReceivedRoute) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.routeKey(route)
	delete(s.routes, key)
	s.routeHistory = append(s.routeHistory, RouteEvent{
		Route:      route,
		Timestamp:  time.Now(),
		IsWithdraw: true,
	})
}

// Get retrieves a route by prefix.
func (s *RouteStore) Get(prefix netip.Prefix) (*ReceivedRoute, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := prefix.String()
	route, ok := s.routes[key]
	return route, ok
}

// GetAll returns all stored routes.
func (s *RouteStore) GetAll() []*ReceivedRoute {
	s.mu.RLock()
	defer s.mu.RUnlock()

	routes := make([]*ReceivedRoute, 0, len(s.routes))
	for _, route := range s.routes {
		routes = append(routes, route)
	}
	return routes
}

// GetByFamily returns all routes of a specific address family.
func (s *RouteStore) GetByFamily(family AddressFamily) []*ReceivedRoute {
	s.mu.RLock()
	defer s.mu.RUnlock()

	routes := make([]*ReceivedRoute, 0)
	for _, route := range s.routes {
		if route.Family == family {
			routes = append(routes, route)
		}
	}
	return routes
}

// Count returns the number of stored routes.
func (s *RouteStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.routes)
}

// GetHistory returns all route events.
func (s *RouteStore) GetHistory() []RouteEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	history := make([]RouteEvent, len(s.routeHistory))
	copy(history, s.routeHistory)
	return history
}

// Clear removes all routes and history.
func (s *RouteStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.routes = make(map[string]*ReceivedRoute)
	s.routeHistory = make([]RouteEvent, 0)
}

// routeKey generates a unique key for a route.
func (s *RouteStore) routeKey(route *ReceivedRoute) string {
	if route.EVPNRoute != nil {
		// For EVPN routes, include type and relevant identifiers
		switch route.EVPNRoute.Type {
		case EVPNTypeMACIP:
			return "evpn-2:" + route.EVPNRoute.MAC.String() + ":" + route.EVPNRoute.IP.String()
		case EVPNTypeMulticast:
			return "evpn-3:" + route.EVPNRoute.OriginatingIP.String()
		case EVPNTypeIPPrefix:
			return "evpn-5:" + route.EVPNRoute.IPPrefix.String()
		}
	}
	return route.Prefix.String()
}

// StateChangeEvent records a peer state change.
type StateChangeEvent struct {
	// PeerAddress is the address of the peer.
	PeerAddress netip.Addr

	// OldState is the previous state.
	OldState PeerState

	// NewState is the new state.
	NewState PeerState

	// Timestamp is when this event occurred.
	Timestamp time.Time
}

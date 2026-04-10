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
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

// TestNewMockBGPPeer tests creating a new mock BGP peer.
func TestNewMockBGPPeer(t *testing.T) {
	tests := []struct {
		name      string
		config    *MockBGPPeerConfig
		logger    *slog.Logger
		expectErr bool
		errType   error
	}{
		{
			name:      "nil config",
			config:    nil,
			logger:    newTestLogger(),
			expectErr: true,
			errType:   ErrNilConfig,
		},
		{
			name: "nil logger",
			config: &MockBGPPeerConfig{
				ASN:      65001,
				RouterID: "1.1.1.1",
			},
			logger:    nil,
			expectErr: true,
			errType:   ErrNilLogger,
		},
		{
			name: "invalid ASN",
			config: &MockBGPPeerConfig{
				ASN:      0,
				RouterID: "1.1.1.1",
			},
			logger:    newTestLogger(),
			expectErr: true,
			errType:   ErrInvalidASN,
		},
		{
			name: "empty router ID",
			config: &MockBGPPeerConfig{
				ASN:      65001,
				RouterID: "",
			},
			logger:    newTestLogger(),
			expectErr: true,
			errType:   ErrInvalidRouterID,
		},
		{
			name: "invalid router ID format",
			config: &MockBGPPeerConfig{
				ASN:      65001,
				RouterID: "not-an-ip",
			},
			logger:    newTestLogger(),
			expectErr: true,
		},
		{
			name: "valid config",
			config: &MockBGPPeerConfig{
				ASN:        65001,
				RouterID:   "1.1.1.1",
				ListenAddr: ":10179",
			},
			logger:    newTestLogger(),
			expectErr: false,
		},
		{
			name: "valid config with neighbors",
			config: &MockBGPPeerConfig{
				ASN:        65001,
				RouterID:   "1.1.1.1",
				ListenAddr: ":10180",
				Neighbors: []MockNeighborConfig{
					{
						Address: "192.168.1.1",
						ASN:     65002,
					},
				},
			},
			logger:    newTestLogger(),
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peer, err := NewMockBGPPeer(tc.config, tc.logger)

			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tc.errType != nil && err != tc.errType {
					// Check if error type matches (using type assertion for sentinel errors)
					if _, ok := err.(*ErrConfigValidation); !ok && err != tc.errType {
						t.Errorf("expected error type %T, got %T: %v", tc.errType, err, err)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if peer == nil {
				t.Error("expected peer, got nil")
				return
			}

			if peer.Config() != tc.config {
				t.Error("config mismatch")
			}

			if peer.IsStarted() {
				t.Error("peer should not be started")
			}
		})
	}
}

// TestRouteStore tests the route store functionality.
func TestRouteStore(t *testing.T) {
	store := NewRouteStore()

	// Test empty store
	if store.Count() != 0 {
		t.Errorf("expected count 0, got %d", store.Count())
	}

	if routes := store.GetAll(); len(routes) != 0 {
		t.Errorf("expected empty routes, got %d", len(routes))
	}

	// Add routes
	route1 := &ReceivedRoute{
		Family:     AFamilyIPv4Unicast,
		Prefix:     netip.MustParsePrefix("10.0.0.0/24"),
		NextHop:    netip.MustParseAddr("192.168.1.1"),
		ReceivedAt: time.Now(),
	}

	route2 := &ReceivedRoute{
		Family:     AFamilyIPv6Unicast,
		Prefix:     netip.MustParsePrefix("2001:db8::/32"),
		NextHop:    netip.MustParseAddr("2001:db8::1"),
		ReceivedAt: time.Now(),
	}

	store.Add(route1)
	store.Add(route2)

	// Test count
	if store.Count() != 2 {
		t.Errorf("expected count 2, got %d", store.Count())
	}

	// Test GetByFamily
	ipv4Routes := store.GetByFamily(AFamilyIPv4Unicast)
	if len(ipv4Routes) != 1 {
		t.Errorf("expected 1 IPv4 route, got %d", len(ipv4Routes))
	}

	ipv6Routes := store.GetByFamily(AFamilyIPv6Unicast)
	if len(ipv6Routes) != 1 {
		t.Errorf("expected 1 IPv6 route, got %d", len(ipv6Routes))
	}

	// Test Get
	retrieved, ok := store.Get(route1.Prefix)
	if !ok {
		t.Error("expected route to be found")
	}
	if retrieved.Prefix != route1.Prefix {
		t.Error("prefix mismatch")
	}

	// Test history
	history := store.GetHistory()
	if len(history) != 2 {
		t.Errorf("expected 2 history events, got %d", len(history))
	}

	// Test removal
	store.Remove(route1)
	if store.Count() != 1 {
		t.Errorf("expected count 1, got %d", store.Count())
	}

	history = store.GetHistory()
	if len(history) != 3 {
		t.Errorf("expected 3 history events, got %d", len(history))
	}
	if !history[2].IsWithdraw {
		t.Error("last event should be a withdrawal")
	}

	// Test clear
	store.Clear()
	if store.Count() != 0 {
		t.Errorf("expected count 0 after clear, got %d", store.Count())
	}
}

// TestAddressFamily tests the AddressFamily type.
func TestAddressFamily(t *testing.T) {
	tests := []struct {
		family   AddressFamily
		expected string
	}{
		{AFamilyIPv4Unicast, "ipv4-unicast"},
		{AFamilyIPv6Unicast, "ipv6-unicast"},
		{AFamilyEVPN, "l2vpn-evpn"},
		{AddressFamily(99), "unknown"},
	}

	for _, tc := range tests {
		if tc.family.String() != tc.expected {
			t.Errorf("AddressFamily(%d).String() = %s, expected %s",
				tc.family, tc.family.String(), tc.expected)
		}
	}
}

// TestPeerState tests the PeerState type.
func TestPeerState(t *testing.T) {
	tests := []struct {
		state    PeerState
		expected string
		isUp     bool
	}{
		{PeerStateIdle, "Idle", false},
		{PeerStateConnect, "Connect", false},
		{PeerStateActive, "Active", false},
		{PeerStateOpenSent, "OpenSent", false},
		{PeerStateOpenConfirm, "OpenConfirm", false},
		{PeerStateEstablished, "Established", true},
		{PeerState(99), "Unknown", false},
	}

	for _, tc := range tests {
		if tc.state.String() != tc.expected {
			t.Errorf("PeerState(%d).String() = %s, expected %s",
				tc.state, tc.state.String(), tc.expected)
		}
		if tc.state.IsUp() != tc.isUp {
			t.Errorf("PeerState(%d).IsUp() = %v, expected %v",
				tc.state, tc.state.IsUp(), tc.isUp)
		}
	}
}

// TestEVPNRouteType tests the EVPNRouteType type.
func TestEVPNRouteType(t *testing.T) {
	tests := []struct {
		routeType EVPNRouteType
		expected  string
	}{
		{EVPNTypeMACIP, "type-2-mac-ip"},
		{EVPNTypeMulticast, "type-3-multicast"},
		{EVPNTypeIPPrefix, "type-5-prefix"},
		{EVPNRouteType(99), "unknown"},
	}

	for _, tc := range tests {
		if tc.routeType.String() != tc.expected {
			t.Errorf("EVPNRouteType(%d).String() = %s, expected %s",
				tc.routeType, tc.routeType.String(), tc.expected)
		}
	}
}

// TestEVPNRouteBuilder tests the EVPN route builder.
func TestEVPNRouteBuilder(t *testing.T) {
	t.Run("Type2 route", func(t *testing.T) {
		route := NewType2RouteBuilder().
			WithRouteDistinguisher("65001:100").
			WithEthernetTag(0).
			WithMAC("00:11:22:33:44:55").
			WithIP("192.168.1.100").
			WithVNI(10000).
			WithNextHop("10.0.0.1").
			WithASPath(65001, 65002).
			WithOrigin(0).
			Build()

		if route.Family != AFamilyEVPN {
			t.Errorf("expected family EVPN, got %s", route.Family)
		}
		if route.EVPNRoute.Type != EVPNTypeMACIP {
			t.Errorf("expected type MAC/IP, got %s", route.EVPNRoute.Type)
		}
		if route.EVPNRoute.VNI != 10000 {
			t.Errorf("expected VNI 10000, got %d", route.EVPNRoute.VNI)
		}
		if route.NextHop.String() != "10.0.0.1" {
			t.Errorf("expected next-hop 10.0.0.1, got %s", route.NextHop)
		}
	})

	t.Run("Type3 route", func(t *testing.T) {
		route := NewType3RouteBuilder().
			WithRouteDistinguisher("65001:100").
			WithEthernetTag(0).
			WithOriginatingIP("10.0.0.1").
			WithVNI(10000).
			WithNextHop("10.0.0.1").
			Build()

		if route.EVPNRoute.Type != EVPNTypeMulticast {
			t.Errorf("expected type Multicast, got %s", route.EVPNRoute.Type)
		}
		if route.EVPNRoute.OriginatingIP.String() != "10.0.0.1" {
			t.Errorf("expected originating IP 10.0.0.1, got %s",
				route.EVPNRoute.OriginatingIP)
		}
	})

	t.Run("Type5 route", func(t *testing.T) {
		route := NewType5RouteBuilder().
			WithRouteDistinguisher("65001:100").
			WithEthernetTag(0).
			WithPrefix("10.0.0.0/24").
			WithGatewayIP("10.0.0.1").
			WithVNI(10000).
			WithNextHop("10.0.0.1").
			Build()

		if route.EVPNRoute.Type != EVPNTypeIPPrefix {
			t.Errorf("expected type IP Prefix, got %s", route.EVPNRoute.Type)
		}
		if route.EVPNRoute.IPPrefix.String() != "10.0.0.0/24" {
			t.Errorf("expected prefix 10.0.0.0/24, got %s",
				route.EVPNRoute.IPPrefix)
		}
	})
}

// TestEVPNRouteStore tests the EVPN route store.
func TestEVPNRouteStore(t *testing.T) {
	store := NewEVPNRouteStore()

	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Add Type-2 route
	type2Route := &ReceivedRoute{
		Family: AFamilyEVPN,
		EVPNRoute: &EVPNRouteData{
			Type: EVPNTypeMACIP,
			MAC:  mac,
			IP:   netip.MustParseAddr("192.168.1.100"),
			VNI:  10000,
		},
	}
	store.AddRoute(type2Route)

	// Add Type-3 route
	type3Route := &ReceivedRoute{
		Family: AFamilyEVPN,
		EVPNRoute: &EVPNRouteData{
			Type:          EVPNTypeMulticast,
			OriginatingIP: netip.MustParseAddr("10.0.0.1"),
			VNI:           10000,
		},
	}
	store.AddRoute(type3Route)

	// Add Type-5 route
	type5Route := &ReceivedRoute{
		Family: AFamilyEVPN,
		EVPNRoute: &EVPNRouteData{
			Type:     EVPNTypeIPPrefix,
			IPPrefix: netip.MustParsePrefix("192.168.0.0/16"),
			VNI:      10000,
		},
	}
	store.AddRoute(type5Route)

	// Test counts
	if store.TotalCount() != 3 {
		t.Errorf("expected total count 3, got %d", store.TotalCount())
	}

	if store.CountByType(EVPNTypeMACIP) != 1 {
		t.Errorf("expected 1 MAC/IP route, got %d", store.CountByType(EVPNTypeMACIP))
	}

	if store.CountByType(EVPNTypeMulticast) != 1 {
		t.Errorf("expected 1 multicast route, got %d", store.CountByType(EVPNTypeMulticast))
	}

	if store.CountByType(EVPNTypeIPPrefix) != 1 {
		t.Errorf("expected 1 prefix route, got %d", store.CountByType(EVPNTypeIPPrefix))
	}

	// Test retrieval
	retrieved, ok := store.GetMACIPRoute(10000, mac, netip.MustParseAddr("192.168.1.100"))
	if !ok {
		t.Error("expected MAC/IP route to be found")
	}
	if retrieved.EVPNRoute.MAC.String() != mac.String() {
		t.Error("MAC mismatch")
	}

	retrieved, ok = store.GetMulticastRoute(10000, netip.MustParseAddr("10.0.0.1"))
	if !ok {
		t.Error("expected multicast route to be found")
	}

	retrieved, ok = store.GetPrefixRoute(10000, netip.MustParsePrefix("192.168.0.0/16"))
	if !ok {
		t.Error("expected prefix route to be found")
	}

	// Test GetByVNI
	macIPRoutes := store.GetMACIPRoutesByVNI(10000)
	if len(macIPRoutes) != 1 {
		t.Errorf("expected 1 MAC/IP route for VNI 10000, got %d", len(macIPRoutes))
	}

	// Test removal
	store.RemoveRoute(type2Route)
	if store.CountByType(EVPNTypeMACIP) != 0 {
		t.Errorf("expected 0 MAC/IP routes after removal, got %d",
			store.CountByType(EVPNTypeMACIP))
	}

	// Test clear
	store.Clear()
	if store.TotalCount() != 0 {
		t.Errorf("expected 0 routes after clear, got %d", store.TotalCount())
	}
}

// TestBuildEVPNNLRI tests building EVPN NLRI bytes.
func TestBuildEVPNNLRI(t *testing.T) {
	t.Run("Type2 NLRI", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		nlri := BuildType2NLRI(10000, mac, ip, 65001, 100)

		if len(nlri) < 2 {
			t.Fatal("NLRI too short")
		}

		if nlri[0] != byte(EVPNTypeMACIP) {
			t.Errorf("expected route type %d, got %d", EVPNTypeMACIP, nlri[0])
		}

		// Parse it back
		parsed, err := ParseEVPNNLRI(nlri)
		if err != nil {
			t.Fatalf("failed to parse NLRI: %v", err)
		}

		if parsed.Type != EVPNTypeMACIP {
			t.Errorf("expected type %s, got %s", EVPNTypeMACIP, parsed.Type)
		}

		if parsed.MAC.String() != mac.String() {
			t.Errorf("expected MAC %s, got %s", mac, parsed.MAC)
		}

		if parsed.IP.String() != ip.String() {
			t.Errorf("expected IP %s, got %s", ip, parsed.IP)
		}

		if parsed.VNI != 10000 {
			t.Errorf("expected VNI 10000, got %d", parsed.VNI)
		}
	})

	t.Run("Type3 NLRI", func(t *testing.T) {
		vtep := netip.MustParseAddr("10.0.0.1")

		nlri := BuildType3NLRI(10000, vtep, 65001, 100)

		if nlri[0] != byte(EVPNTypeMulticast) {
			t.Errorf("expected route type %d, got %d", EVPNTypeMulticast, nlri[0])
		}

		// Parse it back
		parsed, err := ParseEVPNNLRI(nlri)
		if err != nil {
			t.Fatalf("failed to parse NLRI: %v", err)
		}

		if parsed.Type != EVPNTypeMulticast {
			t.Errorf("expected type %s, got %s", EVPNTypeMulticast, parsed.Type)
		}

		if parsed.OriginatingIP.String() != vtep.String() {
			t.Errorf("expected originating IP %s, got %s", vtep, parsed.OriginatingIP)
		}
	})

	t.Run("Type5 NLRI", func(t *testing.T) {
		prefix := netip.MustParsePrefix("192.168.0.0/16")
		gateway := netip.MustParseAddr("192.168.1.1")

		nlri := BuildType5NLRI(10000, prefix, gateway, 65001, 100)

		if nlri[0] != byte(EVPNTypeIPPrefix) {
			t.Errorf("expected route type %d, got %d", EVPNTypeIPPrefix, nlri[0])
		}

		// Parse it back
		parsed, err := ParseEVPNNLRI(nlri)
		if err != nil {
			t.Fatalf("failed to parse NLRI: %v", err)
		}

		if parsed.Type != EVPNTypeIPPrefix {
			t.Errorf("expected type %s, got %s", EVPNTypeIPPrefix, parsed.Type)
		}

		if parsed.IPPrefix.String() != prefix.String() {
			t.Errorf("expected prefix %s, got %s", prefix, parsed.IPPrefix)
		}

		if parsed.GatewayIP.String() != gateway.String() {
			t.Errorf("expected gateway %s, got %s", gateway, parsed.GatewayIP)
		}

		if parsed.VNI != 10000 {
			t.Errorf("expected VNI 10000, got %d", parsed.VNI)
		}
	})
}

// TestMockBGPPeerStartStop tests starting and stopping the mock peer.
func TestMockBGPPeerStartStop(t *testing.T) {
	config := &MockBGPPeerConfig{
		ASN:        65001,
		RouterID:   "1.1.1.1",
		ListenAddr: ":10181",
	}

	peer, err := NewMockBGPPeer(config, newTestLogger())
	if err != nil {
		t.Fatalf("failed to create peer: %v", err)
	}

	// Test start
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := peer.Start(ctx); err != nil {
		t.Fatalf("failed to start peer: %v", err)
	}

	if !peer.IsStarted() {
		t.Error("peer should be started")
	}

	// Test double start
	if err := peer.Start(ctx); err != ErrPeerAlreadyStarted {
		t.Errorf("expected ErrPeerAlreadyStarted, got %v", err)
	}

	// Test stop
	if err := peer.Stop(ctx); err != nil {
		t.Fatalf("failed to stop peer: %v", err)
	}

	if peer.IsStarted() {
		t.Error("peer should not be started")
	}
}

// TestMockBGPServerRouteInjection tests route injection functionality.
func TestMockBGPServerRouteInjection(t *testing.T) {
	config := &MockBGPPeerConfig{
		ASN:        65001,
		RouterID:   "1.1.1.1",
		ListenAddr: ":10182",
	}

	server, err := NewMockBGPServer(config, newTestLogger())
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		if err := server.Stop(ctx); err != nil {
			t.Logf("failed to stop server: %v", err)
		}
	}()

	// Test route injection
	route := &RouteInjection{
		Family:    AFamilyIPv4Unicast,
		Prefix:    netip.MustParsePrefix("10.0.0.0/24"),
		NextHop:   netip.MustParseAddr("1.1.1.1"),
		ASPath:    []uint32{65001},
		LocalPref: 100,
		Origin:    0,
	}

	if err := server.InjectRoute(ctx, route); err != nil {
		t.Fatalf("failed to inject route: %v", err)
	}

	// Test route withdrawal
	if err := server.WithdrawRoute(ctx, AFamilyIPv4Unicast, route.Prefix); err != nil {
		t.Fatalf("failed to withdraw route: %v", err)
	}
}

// TestValidateRouteInjection tests route injection validation.
func TestValidateRouteInjection(t *testing.T) {
	tests := []struct {
		name      string
		route     *RouteInjection
		expectErr bool
	}{
		{
			name: "valid IPv4 route",
			route: &RouteInjection{
				Family:  AFamilyIPv4Unicast,
				Prefix:  netip.MustParsePrefix("10.0.0.0/24"),
				NextHop: netip.MustParseAddr("192.168.1.1"),
			},
			expectErr: false,
		},
		{
			name: "valid IPv6 route",
			route: &RouteInjection{
				Family:  AFamilyIPv6Unicast,
				Prefix:  netip.MustParsePrefix("2001:db8::/32"),
				NextHop: netip.MustParseAddr("2001:db8::1"),
			},
			expectErr: false,
		},
		{
			name: "invalid prefix",
			route: &RouteInjection{
				Family:  AFamilyIPv4Unicast,
				Prefix:  netip.Prefix{},
				NextHop: netip.MustParseAddr("192.168.1.1"),
			},
			expectErr: true,
		},
		{
			name: "invalid next-hop",
			route: &RouteInjection{
				Family:  AFamilyIPv4Unicast,
				Prefix:  netip.MustParsePrefix("10.0.0.0/24"),
				NextHop: netip.Addr{},
			},
			expectErr: true,
		},
		{
			name: "EVPN route (no validation for prefix/nh)",
			route: &RouteInjection{
				Family: AFamilyEVPN,
				EVPNRoute: &EVPNRouteData{
					Type: EVPNTypeMACIP,
				},
			},
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRouteInjection(tc.route)
			if tc.expectErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestHelperFunctions tests helper functions.
func TestHelperFunctions(t *testing.T) {
	t.Run("splitHostPort", func(t *testing.T) {
		tests := []struct {
			addr string
			host string
			port string
		}{
			{"192.168.1.1:179", "192.168.1.1", "179"},
			{":179", "", "179"},
			{"192.168.1.1", "192.168.1.1", ""},
		}

		for _, tc := range tests {
			host, port, _ := splitHostPort(tc.addr)
			if host != tc.host {
				t.Errorf("splitHostPort(%q) host = %q, expected %q", tc.addr, host, tc.host)
			}
			if port != tc.port {
				t.Errorf("splitHostPort(%q) port = %q, expected %q", tc.addr, port, tc.port)
			}
		}
	})

	t.Run("parsePort", func(t *testing.T) {
		tests := []struct {
			s        string
			expected int
		}{
			{"179", 179},
			{"10179", 10179},
			{"0", 0},
			{"abc", 0},
		}

		for _, tc := range tests {
			result := parsePort(tc.s)
			if result != tc.expected {
				t.Errorf("parsePort(%q) = %d, expected %d", tc.s, result, tc.expected)
			}
		}
	})

	t.Run("intToStr", func(t *testing.T) {
		tests := []struct {
			n        int
			expected string
		}{
			{0, "0"},
			{123, "123"},
			{-456, "-456"},
			{1000000, "1000000"},
		}

		for _, tc := range tests {
			result := intToStr(tc.n)
			if result != tc.expected {
				t.Errorf("intToStr(%d) = %q, expected %q", tc.n, result, tc.expected)
			}
		}
	})

	t.Run("uint32ToStr", func(t *testing.T) {
		tests := []struct {
			n        uint32
			expected string
		}{
			{0, "0"},
			{123, "123"},
			{4294967295, "4294967295"},
		}

		for _, tc := range tests {
			result := uint32ToStr(tc.n)
			if result != tc.expected {
				t.Errorf("uint32ToStr(%d) = %q, expected %q", tc.n, result, tc.expected)
			}
		}
	})

	t.Run("parseMAC", func(t *testing.T) {
		tests := []struct {
			s        string
			expected string
		}{
			{"00:11:22:33:44:55", "00:11:22:33:44:55"},
			{"00-11-22-33-44-55", "00:11:22:33:44:55"},
			{"001122334455", "00:11:22:33:44:55"},
		}

		for _, tc := range tests {
			mac, err := parseMAC(tc.s)
			if err != nil {
				t.Errorf("parseMAC(%q) error: %v", tc.s, err)
				continue
			}
			result := net.HardwareAddr(mac).String()
			if result != tc.expected {
				t.Errorf("parseMAC(%q) = %q, expected %q", tc.s, result, tc.expected)
			}
		}
	})
}

// TestErrors tests error types.
func TestErrors(t *testing.T) {
	t.Run("sentinel errors", func(t *testing.T) {
		sentinels := []error{
			ErrPeerNotStarted,
			ErrPeerAlreadyStarted,
			ErrInvalidConfig,
			ErrInvalidASN,
			ErrInvalidRouterID,
			ErrInvalidListenAddr,
			ErrNeighborNotFound,
			ErrNeighborExists,
			ErrSessionNotEstablished,
			ErrInvalidPrefix,
			ErrInvalidNextHop,
			ErrNilConfig,
			ErrNilLogger,
		}

		for _, err := range sentinels {
			if err.Error() == "" {
				t.Errorf("error %T has empty message", err)
			}
		}
	})

	t.Run("ErrServerOperationFailed", func(t *testing.T) {
		cause := ErrInvalidConfig
		err := &ErrServerOperationFailed{
			Operation: "test",
			Cause:     cause,
		}

		if err.Error() == "" {
			t.Error("error message is empty")
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() did not return cause")
		}
	})

	t.Run("ErrPeerOperationFailed", func(t *testing.T) {
		cause := ErrNeighborNotFound
		err := &ErrPeerOperationFailed{
			Operation:   "add",
			PeerAddress: netip.MustParseAddr("192.168.1.1"),
			Cause:       cause,
		}

		if err.Error() == "" {
			t.Error("error message is empty")
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() did not return cause")
		}
	})

	t.Run("ErrRouteOperationFailed", func(t *testing.T) {
		cause := ErrInvalidPrefix
		err := &ErrRouteOperationFailed{
			Operation: "inject",
			Prefix:    netip.MustParsePrefix("10.0.0.0/24"),
			Cause:     cause,
		}

		if err.Error() == "" {
			t.Error("error message is empty")
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() did not return cause")
		}
	})

	t.Run("ErrConfigValidation", func(t *testing.T) {
		err := &ErrConfigValidation{
			Field:  "RouterID",
			Value:  "invalid",
			Reason: "must be valid IP",
		}

		if err.Error() == "" {
			t.Error("error message is empty")
		}

		errNoValue := &ErrConfigValidation{
			Field:  "ASN",
			Reason: "must be > 0",
		}

		if errNoValue.Error() == "" {
			t.Error("error message is empty")
		}
	})

	t.Run("ErrWaitTimeout", func(t *testing.T) {
		err := &ErrWaitTimeout{
			Condition: "session established",
			Duration:  "30s",
		}

		if err.Error() == "" {
			t.Error("error message is empty")
		}
	})
}

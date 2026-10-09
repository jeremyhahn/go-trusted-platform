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

package gateway

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// PortState Benchmarks

func BenchmarkPortState_String(b *testing.B) {
	states := []PortState{
		PortStateUnknown,
		PortStateUp,
		PortStateDown,
		PortStateError,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.String()
	}
}

func BenchmarkPortState_Valid(b *testing.B) {
	states := []PortState{
		PortStateUnknown,
		PortStateUp,
		PortStateDown,
		PortStateError,
		PortState(100), // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.Valid()
	}
}

func BenchmarkPortState_IsUp(b *testing.B) {
	states := []PortState{
		PortStateUp,
		PortStateDown,
		PortStateError,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.IsUp()
	}
}

// GatewayState Benchmarks

func BenchmarkGatewayState_String(b *testing.B) {
	states := []GatewayState{
		GatewayStateUnknown,
		GatewayStateInitializing,
		GatewayStateRunning,
		GatewayStateDegraded,
		GatewayStateStopping,
		GatewayStateStopped,
		GatewayStateError,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.String()
	}
}

func BenchmarkGatewayState_Valid(b *testing.B) {
	states := []GatewayState{
		GatewayStateRunning,
		GatewayStateDegraded,
		GatewayStateStopped,
		GatewayState(100), // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.Valid()
	}
}

func BenchmarkGatewayState_IsHealthy(b *testing.B) {
	states := []GatewayState{
		GatewayStateRunning,
		GatewayStateDegraded,
		GatewayStateStopped,
		GatewayStateError,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.IsHealthy()
	}
}

func BenchmarkGatewayState_IsOperational(b *testing.B) {
	states := []GatewayState{
		GatewayStateRunning,
		GatewayStateDegraded,
		GatewayStateStopped,
		GatewayStateError,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.IsOperational()
	}
}

// UplinkPort Benchmarks

func BenchmarkUplinkPort_Valid(b *testing.B) {
	ports := []*UplinkPort{
		{Name: "eth0", MTU: 9000, Speed: 10_000_000_000},
		{Name: "eth1", MTU: 1500, Speed: 1_000_000_000},
		{Name: "", MTU: 9000, Speed: 10_000_000_000},  // Invalid
		{Name: "eth0", MTU: 0, Speed: 10_000_000_000}, // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		port := ports[i%len(ports)]
		_ = port.Valid()
	}
}

// GatewayNode Benchmarks

func BenchmarkGatewayNode_MeetsMinReputation(b *testing.B) {
	nodes := []*GatewayNode{
		{Reputation: 0.90},
		{Reputation: 0.80},
		{Reputation: 0.85},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node := nodes[i%len(nodes)]
		_ = node.MeetsMinReputation()
	}
}

func BenchmarkGatewayNode_MeetsMinAge(b *testing.B) {
	nodes := []*GatewayNode{
		{Age: 180 * 24 * time.Hour},
		{Age: 100 * 24 * time.Hour},
		{Age: 175 * 24 * time.Hour},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node := nodes[i%len(nodes)]
		_ = node.MeetsMinAge()
	}
}

func BenchmarkGatewayNode_MeetsMinUptime(b *testing.B) {
	nodes := []*GatewayNode{
		{Uptime: 98.0},
		{Uptime: 90.0},
		{Uptime: 95.0},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node := nodes[i%len(nodes)]
		_ = node.MeetsMinUptime()
	}
}

func BenchmarkGatewayNode_MeetsAllRequirements(b *testing.B) {
	nodes := []*GatewayNode{
		{Reputation: 0.90, Age: 180 * 24 * time.Hour, Uptime: 98.0},
		{Reputation: 0.80, Age: 180 * 24 * time.Hour, Uptime: 98.0},
		{Reputation: 0.90, Age: 100 * 24 * time.Hour, Uptime: 98.0},
		{Reputation: 0.90, Age: 180 * 24 * time.Hour, Uptime: 90.0},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node := nodes[i%len(nodes)]
		_ = node.MeetsAllRequirements()
	}
}

// GatewayCapabilities Benchmarks

func BenchmarkDefaultCapabilities(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DefaultCapabilities()
	}
}

// UplinkConfig Benchmarks

func BenchmarkUplinkConfig_Validate(b *testing.B) {
	configs := []*UplinkConfig{
		{Name: "eth0", MTU: 9000},
		{Name: "", MTU: 9000},  // Invalid
		{Name: "eth0", MTU: 0}, // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := configs[i%len(configs)]
		_ = config.Validate()
	}
}

// EdgeConfig Benchmarks

func BenchmarkEdgeConfig_Validate(b *testing.B) {
	configs := []*EdgeConfig{
		{Enabled: true, MaxDevices: 100, MaxServices: 50},
		{Enabled: false},
		{Enabled: true, MaxDevices: 0, MaxServices: 50},  // Invalid
		{Enabled: true, MaxDevices: 100, MaxServices: 0}, // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := configs[i%len(configs)]
		_ = config.Validate()
	}
}

// GatewayConfig Benchmarks

func BenchmarkGatewayConfig_Validate(b *testing.B) {
	configs := []*GatewayConfig{
		{
			Enabled:       true,
			ID:            "gw-1",
			NodeID:        1,
			MinReputation: MinReputation,
			MinAgeDays:    MinAgeDays,
			MinUptimePct:  MinUptimePct,
			Overlay:       validOverlayServiceConfig(),
		},
		{Enabled: false},
		{Enabled: true, ID: ""}, // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := configs[i%len(configs)]
		_ = config.Validate()
	}
}

// OverlayGatewayState Benchmarks

func BenchmarkOverlayGatewayState_Create(b *testing.B) {
	remoteVTEPs := make([]netip.Addr, 10)
	for i := 0; i < 10; i++ {
		remoteVTEPs[i] = netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i+1))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = &OverlayGatewayState{
			ActiveVNIs:           100,
			TunnelCount:          50,
			RemoteVTEPs:          remoteVTEPs,
			EVPNRoutesReceived:   1000,
			EVPNRoutesAdvertised: 500,
			LastBGPUpdate:        time.Now(),
		}
	}
}

// EdgeGatewayState Benchmarks

func BenchmarkEdgeGatewayState_Create(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = &EdgeGatewayState{
			ConnectedDevices:        100,
			ActiveServices:          50,
			NATSessionCount:         1000,
			LoadBalancedConnections: 500,
			LastHealthCheck:         time.Now(),
		}
	}
}

// TransitGatewayState Benchmarks

func BenchmarkTransitGatewayState_Create(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = &TransitGatewayState{
			AnnouncedPrefixes:     100,
			ReceivedPrefixes:      500,
			BGPPeersEstablished:   10,
			IPv6PrefixesAnnounced: 50,
			IPv4PrefixesAnnounced: 50,
			LastRouteUpdate:       time.Now(),
		}
	}
}

// UplinkPort Creation Benchmarks

func BenchmarkUplinkPort_Create(b *testing.B) {
	mac, _ := net.ParseMAC("52:54:00:aa:bb:cc")
	ipAddrs := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("192.168.1.1"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = &UplinkPort{
			Name:        "eth0",
			VLAN:        100,
			Speed:       10_000_000_000,
			MTU:         9000,
			State:       PortStateUp,
			IPAddresses: ipAddrs,
			MACAddress:  mac,
		}
	}
}

// Parallel Benchmarks

func BenchmarkGatewayNode_MeetsAllRequirements_Parallel(b *testing.B) {
	nodes := []*GatewayNode{
		{Reputation: 0.90, Age: 180 * 24 * time.Hour, Uptime: 98.0},
		{Reputation: 0.80, Age: 180 * 24 * time.Hour, Uptime: 98.0},
		{Reputation: 0.90, Age: 100 * 24 * time.Hour, Uptime: 98.0},
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			node := nodes[i%len(nodes)]
			_ = node.MeetsAllRequirements()
			i++
		}
	})
}

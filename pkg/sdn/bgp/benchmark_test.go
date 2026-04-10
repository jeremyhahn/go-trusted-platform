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
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

// RouteDistinguisher Benchmarks

func BenchmarkRouteDistinguisher_Bytes(b *testing.B) {
	rds := []RouteDistinguisher{
		{Type: 0, Administrator: 65001, AssignedNumber: 100},
		{Type: 1, Administrator: binary.BigEndian.Uint32(net.ParseIP("10.0.0.1").To4()), AssignedNumber: 100},
		{Type: 2, Administrator: 4200000001, AssignedNumber: 100},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rd := rds[i%len(rds)]
		_ = rd.Bytes()
	}
}

func BenchmarkParseRouteDistinguisher(b *testing.B) {
	data := [8]byte{0x00, 0x00, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseRouteDistinguisher(data)
	}
}

// RouteTarget Benchmarks

func BenchmarkRouteTarget_Bytes(b *testing.B) {
	rts := []RouteTarget{
		{Type: 0, GlobalAdmin: 65001, LocalAdmin: 1000100},
		{Type: 1, GlobalAdmin: binary.BigEndian.Uint32(net.ParseIP("10.0.0.1").To4()), LocalAdmin: 100},
		{Type: 2, GlobalAdmin: 4200000001, LocalAdmin: 100},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rt := rts[i%len(rts)]
		_ = rt.Bytes()
	}
}

func BenchmarkParseRouteTarget(b *testing.B) {
	data := [8]byte{0x00, 0x02, 0xFD, 0xE9, 0x00, 0x0F, 0x42, 0x64}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseRouteTarget(data)
	}
}

// MACIPEntry Benchmarks

func BenchmarkMACIPEntry_Key(b *testing.B) {
	entry := &MACIPEntry{
		MAC:    net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
		IP:     netip.MustParseAddr("10.0.0.100"),
		VNI:    1000100,
		VTEPIP: netip.MustParseAddr("192.168.1.1"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entry.Key()
	}
}

func BenchmarkMACIPEntry_MACIPKey(b *testing.B) {
	entry := &MACIPEntry{
		MAC:    net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
		IP:     netip.MustParseAddr("10.0.0.100"),
		VNI:    1000100,
		VTEPIP: netip.MustParseAddr("192.168.1.1"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entry.MACIPKey()
	}
}

func BenchmarkMACIPEntry_Clone(b *testing.B) {
	entry := &MACIPEntry{
		MAC:           net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
		IP:            netip.MustParseAddr("10.0.0.100"),
		VNI:           1000100,
		VTEPIP:        netip.MustParseAddr("192.168.1.1"),
		Sequence:      1,
		EthernetTagID: 0,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entry.Clone()
	}
}

// IMETEntry Benchmarks

func BenchmarkIMETEntry_Key(b *testing.B) {
	entry := &IMETEntry{
		VNI:           1000100,
		VTEPIP:        netip.MustParseAddr("192.168.1.1"),
		EthernetTagID: 0,
		TunnelType:    TunnelTypeIngressReplication,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entry.Key()
	}
}

func BenchmarkIMETEntry_Clone(b *testing.B) {
	entry := &IMETEntry{
		VNI:           1000100,
		VTEPIP:        netip.MustParseAddr("192.168.1.1"),
		EthernetTagID: 0,
		TunnelType:    TunnelTypeIngressReplication,
		CreatedAt:     time.Now(),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entry.Clone()
	}
}

// PrefixRoute Benchmarks

func BenchmarkPrefixRoute_Key(b *testing.B) {
	route := &PrefixRoute{
		Prefix:    netip.MustParsePrefix("10.0.0.0/24"),
		VNI:       1000100,
		GatewayIP: netip.MustParseAddr("10.0.0.1"),
		NextHop:   netip.MustParseAddr("192.168.1.1"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = route.Key()
	}
}

func BenchmarkPrefixRoute_Clone(b *testing.B) {
	route := &PrefixRoute{
		Prefix:        netip.MustParsePrefix("10.0.0.0/24"),
		VNI:           1000100,
		GatewayIP:     netip.MustParseAddr("10.0.0.1"),
		NextHop:       netip.MustParseAddr("192.168.1.1"),
		EthernetTagID: 0,
		RouteTargets: []RouteTarget{
			{Type: 0, GlobalAdmin: 65001, LocalAdmin: 1000100},
		},
		GatewayMAC: net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = route.Clone()
	}
}

// EVPNRouteData Benchmarks

func BenchmarkEVPNRouteData_Clone(b *testing.B) {
	route := &EVPNRouteData{
		Type: EVPNTypeMACIPAdvertisement,
		RD:   RouteDistinguisher{Type: 0, Administrator: 65001, AssignedNumber: 100},
		RouteTargets: []RouteTarget{
			{Type: 0, GlobalAdmin: 65001, LocalAdmin: 1000100},
		},
		MACIP: &MACIPEntry{
			MAC:    net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
			IP:     netip.MustParseAddr("10.0.0.100"),
			VNI:    1000100,
			VTEPIP: netip.MustParseAddr("192.168.1.1"),
		},
		NextHop:    netip.MustParseAddr("192.168.1.1"),
		Label:      1000100,
		IsWithdraw: false,
		ReceivedAt: time.Now(),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = route.Clone()
	}
}

// Dampening Benchmarks

// benchDampeningSpeaker implements DampeningSpeakerInterface for benchmarks
type benchDampeningSpeaker struct {
	started bool
}

func (m *benchDampeningSpeaker) IsStarted() bool {
	return m.started
}

func (m *benchDampeningSpeaker) SuppressRoute(ctx context.Context, prefix netip.Prefix) error {
	return nil
}

func (m *benchDampeningSpeaker) UnsuppressRoute(ctx context.Context, prefix netip.Prefix) error {
	return nil
}

func BenchmarkDampeningConfig_Validate(b *testing.B) {
	config := DefaultDampeningConfig()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Validate()
	}
}

func BenchmarkDampeningManager_RecordFlap(b *testing.B) {
	speaker := &benchDampeningSpeaker{started: true}
	config := DefaultDampeningConfig()
	logger := slog.Default()

	manager, err := NewDampeningManager(speaker, config, logger)
	if err != nil {
		b.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		b.Fatal(err)
	}

	prefixes := make([]netip.Prefix, 100)
	for i := 0; i < 100; i++ {
		prefixes[i] = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prefix := prefixes[i%len(prefixes)]
		_ = manager.RecordFlap(prefix)
	}
}

func BenchmarkDampeningManager_IsSuppressed(b *testing.B) {
	speaker := &benchDampeningSpeaker{started: true}
	config := DefaultDampeningConfig()
	logger := slog.Default()

	manager, err := NewDampeningManager(speaker, config, logger)
	if err != nil {
		b.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		b.Fatal(err)
	}

	// Pre-populate with flaps
	prefixes := make([]netip.Prefix, 100)
	for i := 0; i < 100; i++ {
		prefixes[i] = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
		// Record enough flaps to suppress some routes
		for j := 0; j < 3; j++ {
			_ = manager.RecordFlap(prefixes[i])
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prefix := prefixes[i%len(prefixes)]
		_ = manager.IsSuppressed(prefix)
	}
}

func BenchmarkDampeningManager_GetDampeningState(b *testing.B) {
	speaker := &benchDampeningSpeaker{started: true}
	config := DefaultDampeningConfig()
	logger := slog.Default()

	manager, err := NewDampeningManager(speaker, config, logger)
	if err != nil {
		b.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		b.Fatal(err)
	}

	prefixes := make([]netip.Prefix, 100)
	for i := 0; i < 100; i++ {
		prefixes[i] = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
		_ = manager.RecordFlap(prefixes[i])
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prefix := prefixes[i%len(prefixes)]
		_, _ = manager.GetDampeningState(prefix)
	}
}

func BenchmarkDampeningManager_ListSuppressedRoutes(b *testing.B) {
	speaker := &benchDampeningSpeaker{started: true}
	config := DefaultDampeningConfig()
	logger := slog.Default()

	manager, err := NewDampeningManager(speaker, config, logger)
	if err != nil {
		b.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		b.Fatal(err)
	}

	// Pre-populate with suppressed routes
	for i := 0; i < 50; i++ {
		prefix := netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
		// Record enough flaps to suppress
		for j := 0; j < 5; j++ {
			_ = manager.RecordFlap(prefix)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.ListSuppressedRoutes()
	}
}

// Sub-benchmarks for different route counts
func BenchmarkDampeningManager_RecordFlap_Sizes(b *testing.B) {
	sizes := []int{10, 100, 1000, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("routes_%d", size), func(b *testing.B) {
			speaker := &benchDampeningSpeaker{started: true}
			config := DefaultDampeningConfig()
			logger := slog.Default()

			manager, err := NewDampeningManager(speaker, config, logger)
			if err != nil {
				b.Fatal(err)
			}
			if err := manager.Start(context.Background()); err != nil {
				b.Fatal(err)
			}

			// Pre-populate with routes
			prefixes := make([]netip.Prefix, size)
			for i := 0; i < size; i++ {
				prefixes[i] = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
				_ = manager.RecordFlap(prefixes[i])
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				prefix := prefixes[i%len(prefixes)]
				_ = manager.RecordFlap(prefix)
			}
		})
	}
}

// PeerState Benchmarks

func BenchmarkPeerState_String(b *testing.B) {
	states := []PeerState{
		PeerStateIdle,
		PeerStateConnect,
		PeerStateActive,
		PeerStateOpenSent,
		PeerStateOpenConfirm,
		PeerStateEstablished,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.String()
	}
}

func BenchmarkPeerState_Valid(b *testing.B) {
	states := []PeerState{
		PeerStateIdle,
		PeerStateEstablished,
		PeerState(10), // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.Valid()
	}
}

func BenchmarkPeerState_IsUp(b *testing.B) {
	states := []PeerState{
		PeerStateIdle,
		PeerStateConnect,
		PeerStateEstablished,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.IsUp()
	}
}

// AddressFamily Benchmarks

func BenchmarkAddressFamily_String(b *testing.B) {
	families := []AddressFamily{
		AFamilyIPv4Unicast,
		AFamilyIPv6Unicast,
		AFamilyEVPN,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		family := families[i%len(families)]
		_ = family.String()
	}
}

// BGPConfig Benchmarks

func BenchmarkBGPConfig_Validate(b *testing.B) {
	config := &BGPConfig{
		RouterID:           netip.MustParseAddr("10.0.0.1"),
		ASN:                65001,
		ListenPort:         179,
		Tier:               SpeakerTierDatacenter,
		RouteDistinguisher: "65001:100",
		Capabilities:       BGPCapabilities{EVPN: true, IPv4Unicast: true},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Validate()
	}
}

func BenchmarkBGPConfig_IsPrivateASN(b *testing.B) {
	configs := []*BGPConfig{
		{ASN: 65001},      // Private 16-bit
		{ASN: 100},        // Public
		{ASN: 4200000001}, // Private 32-bit
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := configs[i%len(configs)]
		_ = config.IsPrivateASN()
	}
}

// NeighborConfig Benchmarks

func BenchmarkNeighborConfig_Validate(b *testing.B) {
	config := &NeighborConfig{
		Address:           netip.MustParseAddr("10.0.0.2"),
		ASN:               65002,
		AuthType:          AuthTypeNone,
		HoldTime:          90,
		KeepaliveInterval: 30,
		ConnectRetry:      120,
		IPv4Unicast:       true,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Validate()
	}
}

func BenchmarkNeighborConfig_HasAnyAFI(b *testing.B) {
	configs := []*NeighborConfig{
		{IPv4Unicast: true},
		{IPv6Unicast: true},
		{EVPN: true},
		{EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast}},
		{}, // None
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := configs[i%len(configs)]
		_ = config.HasAnyAFI()
	}
}

// EVPNRoute Benchmarks

func BenchmarkEVPNRoute_Validate(b *testing.B) {
	routes := []*EVPNRoute{
		{
			Type:               EVPNTypeMACIPAdvertisement,
			RouteDistinguisher: "65001:100",
			MAC:                "52:54:00:aa:bb:cc",
			MACAddress:         net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
		},
		{
			Type:               EVPNTypeInclusiveMulticast,
			RouteDistinguisher: "65001:100",
			OriginatingIP:      netip.MustParseAddr("192.168.1.1"),
		},
		{
			Type:               EVPNTypeIPPrefix,
			RouteDistinguisher: "65001:100",
			IPPrefix:           netip.MustParsePrefix("10.0.0.0/24"),
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		route := routes[i%len(routes)]
		_ = route.Validate()
	}
}

// TransitRoute Benchmarks

func BenchmarkTransitRoute_Validate(b *testing.B) {
	route := &TransitRoute{
		Prefix:  netip.MustParsePrefix("10.0.0.0/24"),
		NextHop: netip.MustParseAddr("192.168.1.1"),
		Origin:  OriginIGP,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = route.Validate()
	}
}

// Parallel Benchmarks

func BenchmarkDampeningManager_RecordFlap_Parallel(b *testing.B) {
	speaker := &benchDampeningSpeaker{started: true}
	config := DefaultDampeningConfig()
	logger := slog.Default()

	manager, err := NewDampeningManager(speaker, config, logger)
	if err != nil {
		b.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		b.Fatal(err)
	}

	prefixes := make([]netip.Prefix, 1000)
	for i := 0; i < 1000; i++ {
		prefixes[i] = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			prefix := prefixes[i%len(prefixes)]
			_ = manager.RecordFlap(prefix)
			i++
		}
	})
}

func BenchmarkDampeningManager_IsSuppressed_Parallel(b *testing.B) {
	speaker := &benchDampeningSpeaker{started: true}
	config := DefaultDampeningConfig()
	logger := slog.Default()

	manager, err := NewDampeningManager(speaker, config, logger)
	if err != nil {
		b.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		b.Fatal(err)
	}

	// Pre-populate
	prefixes := make([]netip.Prefix, 1000)
	for i := 0; i < 1000; i++ {
		prefixes[i] = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
		_ = manager.RecordFlap(prefixes[i])
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			prefix := prefixes[i%len(prefixes)]
			_ = manager.IsSuppressed(prefix)
			i++
		}
	})
}

func BenchmarkMACIPEntry_Key_Parallel(b *testing.B) {
	entries := make([]*MACIPEntry, 100)
	for i := 0; i < 100; i++ {
		entries[i] = &MACIPEntry{
			MAC:    net.HardwareAddr{0x52, 0x54, 0x00, byte(i), 0xbb, 0xcc},
			IP:     netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i)),
			VNI:    uint32(1000000 + i),
			VTEPIP: netip.MustParseAddr("192.168.1.1"),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			entry := entries[i%len(entries)]
			_ = entry.Key()
			i++
		}
	})
}

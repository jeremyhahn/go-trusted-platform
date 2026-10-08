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
	"fmt"
	"log/slog"
	"net/netip"
	"testing"
)

// EVPN Benchmarks

func BenchmarkAutoRouteTarget(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := AutoRouteTarget(65000, 0, uint32(i%int(MaxVNI))+1); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeEVPNPath(b *testing.B) {
	route := testIRBRoute()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := encodeEVPNPath(route); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeEVPNPath(b *testing.B) {
	path, err := encodeEVPNPath(testIRBRoute())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := decodeEVPNPath(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEVPNRouteData_Clone(b *testing.B) {
	route := testIRBRoute()
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
		RouterID:     netip.MustParseAddr("10.0.0.1"),
		ASN:          65001,
		ListenPort:   179,
		Tier:         SpeakerTierDatacenter,
		Capabilities: BGPCapabilities{EVPN: true, IPv4Unicast: true},
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

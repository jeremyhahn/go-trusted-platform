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

package firewall

import (
	"net/netip"
	"testing"
	"time"
)

func BenchmarkConnTrackLookup(b *testing.B) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	now := time.Now()

	// Pre-populate with 100K entries.
	for i := uint16(0); i < 10000; i++ {
		for j := uint16(0); j < 10; j++ {
			tuple := FiveTuple{
				SrcIP:    netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}),
				DstIP:    netip.AddrFrom4([4]byte{172, 16, byte(j), 1}),
				SrcPort:  i + 1024,
				DstPort:  80 + j,
				Protocol: ProtocolTCP,
			}
			ct.Insert(&ConnEntry{
				Tuple:    tuple,
				State:    ConnStateEstablished,
				Created:  now,
				LastSeen: now,
			})
		}
	}

	// Lookup a known entry.
	target := FiveTuple{
		SrcIP:    netip.AddrFrom4([4]byte{10, 0, 39, 16}), // i=10000
		DstIP:    netip.AddrFrom4([4]byte{172, 16, 5, 1}),
		SrcPort:  10000 + 1024,
		DstPort:  85,
		Protocol: ProtocolTCP,
	}
	// Ensure it exists.
	ct.Insert(&ConnEntry{
		Tuple:    target,
		State:    ConnStateEstablished,
		Created:  now,
		LastSeen: now,
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ct.Lookup(target)
	}
}

func BenchmarkConnTrackLookupMiss(b *testing.B) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	now := time.Now()

	for i := uint16(0); i < 10000; i++ {
		tuple := FiveTuple{
			SrcIP:    netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}),
			DstIP:    netip.MustParseAddr("10.0.0.2"),
			SrcPort:  i + 1024,
			DstPort:  80,
			Protocol: ProtocolTCP,
		}
		ct.Insert(&ConnEntry{
			Tuple:    tuple,
			State:    ConnStateEstablished,
			Created:  now,
			LastSeen: now,
		})
	}

	miss := FiveTuple{
		SrcIP:    netip.MustParseAddr("192.168.1.1"),
		DstIP:    netip.MustParseAddr("192.168.1.2"),
		SrcPort:  55555,
		DstPort:  443,
		Protocol: ProtocolTCP,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ct.Lookup(miss)
	}
}

func BenchmarkConnTrackInsert(b *testing.B) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	now := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		port := uint16(i & 0xFFFF)
		ip3 := byte((i >> 16) & 0xFF)
		ip2 := byte((i >> 24) & 0xFF)
		tuple := FiveTuple{
			SrcIP:    netip.AddrFrom4([4]byte{10, ip2, ip3, byte(port)}),
			DstIP:    netip.MustParseAddr("10.0.0.2"),
			SrcPort:  port,
			DstPort:  80,
			Protocol: ProtocolTCP,
		}
		ct.Insert(&ConnEntry{
			Tuple:    tuple,
			State:    ConnStateNew,
			Created:  now,
			LastSeen: now,
		})
	}
}

func BenchmarkFiveTupleHash(b *testing.B) {
	tuple := FiveTuple{
		SrcIP:    netip.MustParseAddr("10.0.0.1"),
		DstIP:    netip.MustParseAddr("10.0.0.2"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: ProtocolTCP,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tuple.hash()
	}
}

func BenchmarkFiveTupleHashIPv6(b *testing.B) {
	tuple := FiveTuple{
		SrcIP:    netip.MustParseAddr("2001:db8::1"),
		DstIP:    netip.MustParseAddr("2001:db8::2"),
		SrcPort:  12345,
		DstPort:  443,
		Protocol: ProtocolTCP,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tuple.hash()
	}
}

func BenchmarkEngineProcessEstablished(b *testing.B) {
	cfg := testConfig()
	engine, err := NewEngine(cfg, testLogger())
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("10.0.0.5"),
		DstIP:    netip.MustParseAddr("8.8.8.8"),
		SrcPort:  45678,
		DstPort:  443,
		Protocol: ProtocolTCP,
		InIface:  "bond0.200",
		OutIface: "eth0",
		Length:   64,
	}

	// Create and establish the connection.
	engine.Process(pkt)
	tuple := FiveTuple{
		SrcIP:    pkt.SrcIP,
		DstIP:    pkt.DstIP,
		SrcPort:  pkt.SrcPort,
		DstPort:  pkt.DstPort,
		Protocol: pkt.Protocol,
	}
	engine.MarkEstablished(tuple)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.Process(pkt)
	}
}

func BenchmarkEngineProcessNew(b *testing.B) {
	cfg := testConfig()
	engine, err := NewEngine(cfg, testLogger())
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		port := uint16(i&0xFFFF) + 1024
		pkt := &PacketInfo{
			SrcIP:    netip.MustParseAddr("10.0.0.5"),
			DstIP:    netip.MustParseAddr("8.8.8.8"),
			SrcPort:  port,
			DstPort:  443,
			Protocol: ProtocolTCP,
			InIface:  "bond0.200",
			OutIface: "eth0",
			Length:   64,
		}
		engine.Process(pkt)
	}
}

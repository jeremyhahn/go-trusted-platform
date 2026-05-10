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
)

func TestNATEngine_DNATPortForward(t *testing.T) {
	rules := []NATRule{
		{
			Name:       "web-forward",
			Type:       NATTypeDNAT,
			FromZone:   "wan",
			DstPort:    8080,
			TargetIP:   netip.MustParseAddr("10.0.0.10"),
			TargetPort: 80,
			Protocol:   ProtocolTCP,
		},
	}
	engine := NewNATEngine(rules, testLogger())

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("203.0.113.1"),
		DstIP:    netip.MustParseAddr("23.143.36.1"),
		SrcPort:  45678,
		DstPort:  8080,
		Protocol: ProtocolTCP,
		SrcZone:  "wan",
	}

	entry := engine.Apply(pkt, DirectionIngress)
	if entry == nil {
		t.Fatal("expected DNAT entry")
	}
	if entry.Type != NATTypeDNAT {
		t.Errorf("type: got %v, want DNAT", entry.Type)
	}
	if entry.TranslatedDst.Addr() != netip.MustParseAddr("10.0.0.10") {
		t.Errorf("translated dst IP: got %v, want 10.0.0.10", entry.TranslatedDst.Addr())
	}
	if entry.TranslatedDst.Port() != 80 {
		t.Errorf("translated dst port: got %d, want 80", entry.TranslatedDst.Port())
	}
}

func TestNATEngine_DNATNoMatch(t *testing.T) {
	rules := []NATRule{
		{
			Name:       "web-forward",
			Type:       NATTypeDNAT,
			FromZone:   "wan",
			DstPort:    8080,
			TargetIP:   netip.MustParseAddr("10.0.0.10"),
			TargetPort: 80,
			Protocol:   ProtocolTCP,
		},
	}
	engine := NewNATEngine(rules, testLogger())

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("203.0.113.1"),
		DstIP:    netip.MustParseAddr("23.143.36.1"),
		SrcPort:  45678,
		DstPort:  443,
		Protocol: ProtocolTCP,
		SrcZone:  "wan",
	}

	entry := engine.Apply(pkt, DirectionIngress)
	if entry != nil {
		t.Error("expected no DNAT match for port 443")
	}
}

func TestNATEngine_SNATMasquerade(t *testing.T) {
	rules := []NATRule{
		{
			Name:       "masquerade-lan",
			Type:       NATTypeSNAT,
			FromZone:   "lan",
			ToZone:     "wan",
			Masquerade: true,
		},
	}
	engine := NewNATEngine(rules, testLogger())

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("10.0.0.5"),
		DstIP:    netip.MustParseAddr("8.8.8.8"),
		SrcPort:  12345,
		DstPort:  53,
		Protocol: ProtocolUDP,
		SrcZone:  "lan",
		DstZone:  "wan",
	}

	entry := engine.Apply(pkt, DirectionEgress)
	if entry == nil {
		t.Fatal("expected SNAT entry")
	}
	if entry.Type != NATTypeSNAT {
		t.Errorf("type: got %v, want SNAT", entry.Type)
	}
	// Masquerade sets translated src to invalid addr as placeholder.
	if entry.TranslatedSrc.Addr().IsValid() {
		t.Errorf("masquerade should set invalid placeholder addr, got %v", entry.TranslatedSrc.Addr())
	}
}

func TestNATEngine_SNATNoMatch(t *testing.T) {
	rules := []NATRule{
		{
			Name:       "masquerade-lan",
			Type:       NATTypeSNAT,
			FromZone:   "lan",
			ToZone:     "wan",
			Masquerade: true,
		},
	}
	engine := NewNATEngine(rules, testLogger())

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("10.0.0.5"),
		DstIP:    netip.MustParseAddr("10.0.0.6"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: ProtocolTCP,
		SrcZone:  "lan",
		DstZone:  "lan",
	}

	entry := engine.Apply(pkt, DirectionEgress)
	if entry != nil {
		t.Error("expected no SNAT match for lan-to-lan")
	}
}

func TestNATEngine_ProtocolFilter(t *testing.T) {
	rules := []NATRule{
		{
			Name:       "tcp-dnat",
			Type:       NATTypeDNAT,
			DstPort:    80,
			TargetIP:   netip.MustParseAddr("10.0.0.10"),
			TargetPort: 8080,
			Protocol:   ProtocolTCP,
		},
	}
	engine := NewNATEngine(rules, testLogger())

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("203.0.113.1"),
		DstIP:    netip.MustParseAddr("23.143.36.1"),
		SrcPort:  45678,
		DstPort:  80,
		Protocol: ProtocolUDP,
	}

	entry := engine.Apply(pkt, DirectionIngress)
	if entry != nil {
		t.Error("TCP-only DNAT should not match UDP packet")
	}
}

func TestNATEngine_EmptyRules(t *testing.T) {
	engine := NewNATEngine(nil, testLogger())

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("10.0.0.1"),
		DstIP:    netip.MustParseAddr("10.0.0.2"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: ProtocolTCP,
	}

	if entry := engine.Apply(pkt, DirectionIngress); entry != nil {
		t.Error("empty rules should produce no NAT")
	}
	if entry := engine.Apply(pkt, DirectionEgress); entry != nil {
		t.Error("empty rules should produce no NAT")
	}
}

func TestNATEngine_ZoneFilterMismatch(t *testing.T) {
	rules := []NATRule{
		{
			Name:       "zone-filtered",
			Type:       NATTypeDNAT,
			FromZone:   "wan",
			ToZone:     "dmz",
			DstPort:    443,
			TargetIP:   netip.MustParseAddr("10.0.0.10"),
			TargetPort: 443,
		},
	}
	engine := NewNATEngine(rules, testLogger())

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("203.0.113.1"),
		DstIP:    netip.MustParseAddr("23.143.36.1"),
		SrcPort:  45678,
		DstPort:  443,
		Protocol: ProtocolTCP,
		SrcZone:  "lan",
		DstZone:  "wan",
	}

	entry := engine.Apply(pkt, DirectionIngress)
	if entry != nil {
		t.Error("expected no match when source zone differs")
	}
}

func TestNATType_String(t *testing.T) {
	tests := []struct {
		typ  NATType
		want string
	}{
		{NATTypeSNAT, "SNAT"},
		{NATTypeDNAT, "DNAT"},
		{NATType(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.typ.String()
		if got != tt.want {
			t.Errorf("NATType(%d).String() = %q, want %q", tt.typ, got, tt.want)
		}
	}
}

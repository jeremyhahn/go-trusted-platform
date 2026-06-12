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

func testConfig() *Config {
	return &Config{
		Enabled:       true,
		DefaultPolicy: "deny",
		Zones: []Zone{
			{
				Name:       "wan",
				Interfaces: []string{"eth0"},
				Policy:     "deny",
			},
			{
				Name:       "lan",
				Interfaces: []string{"bond0.200"},
				Policy:     "allow",
			},
		},
		Rules: []Rule{
			{
				Name:     "allow-established",
				Priority: 1,
				Action:   ActionAllow,
				Match: RuleMatch{
					State: []ConnState{ConnStateEstablished, ConnStateRelated},
				},
			},
			{
				Name:     "allow-lan-to-wan",
				Priority: 10,
				Action:   ActionAllow,
				Match: RuleMatch{
					SrcZone: "lan",
					DstZone: "wan",
				},
			},
			{
				Name:     "allow-dns",
				Priority: 20,
				Action:   ActionAllow,
				Match: RuleMatch{
					DstPort:  53,
					Protocol: ProtocolUDP,
				},
			},
			{
				Name:     "deny-wan-to-lan",
				Priority: 50,
				Action:   ActionDeny,
				Match: RuleMatch{
					SrcZone: "wan",
					DstZone: "lan",
				},
			},
		},
		NAT: NATConfig{
			SNAT: []NATRule{
				{
					Name:       "masquerade",
					Type:       NATTypeSNAT,
					FromZone:   "lan",
					ToZone:     "wan",
					Masquerade: true,
				},
			},
			DNAT: []NATRule{
				{
					Name:       "web-forward",
					Type:       NATTypeDNAT,
					FromZone:   "wan",
					DstPort:    8080,
					TargetIP:   netip.MustParseAddr("10.0.0.10"),
					TargetPort: 80,
					Protocol:   ProtocolTCP,
				},
			},
		},
	}
}

func TestNewEngine(t *testing.T) {
	engine, err := NewEngine(testConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestNewEngine_NilConfig(t *testing.T) {
	_, err := NewEngine(nil, testLogger())
	if err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewEngine_InvalidPolicy(t *testing.T) {
	cfg := testConfig()
	cfg.DefaultPolicy = "maybe"
	_, err := NewEngine(cfg, testLogger())
	if err != ErrInvalidDefaultPolicy {
		t.Errorf("expected ErrInvalidDefaultPolicy, got %v", err)
	}
}

func TestEngine_ProcessNewConnection_LanToWan(t *testing.T) {
	engine, err := NewEngine(testConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
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

	action, natEntry := engine.Process(pkt)
	if action != ActionAllow {
		t.Errorf("action: got %v, want allow", action)
	}
	if natEntry == nil {
		t.Fatal("expected SNAT entry for lan-to-wan")
	}
	if natEntry.Type != NATTypeSNAT {
		t.Errorf("NAT type: got %v, want SNAT", natEntry.Type)
	}
	if engine.ConnTrackCount() != 1 {
		t.Errorf("conntrack count: got %d, want 1", engine.ConnTrackCount())
	}
}

func TestEngine_ProcessEstablishedFastPath(t *testing.T) {
	engine, err := NewEngine(testConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
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

	// First packet: creates conntrack entry.
	engine.Process(pkt)

	// Mark as established (simulating reply traffic).
	tuple := FiveTuple{
		SrcIP:    pkt.SrcIP,
		DstIP:    pkt.DstIP,
		SrcPort:  pkt.SrcPort,
		DstPort:  pkt.DstPort,
		Protocol: pkt.Protocol,
	}
	engine.MarkEstablished(tuple)

	// Second packet: should hit fast path.
	action, _ := engine.Process(pkt)
	if action != ActionAllow {
		t.Errorf("established fast path: got %v, want allow", action)
	}

	stats := engine.Stats()
	if stats.PacketsProcessed != 2 {
		t.Errorf("packets processed: got %d, want 2", stats.PacketsProcessed)
	}
	if stats.PacketsAllowed != 2 {
		t.Errorf("packets allowed: got %d, want 2", stats.PacketsAllowed)
	}
}

func TestEngine_ProcessDenied_WanToLan(t *testing.T) {
	engine, err := NewEngine(testConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("203.0.113.1"),
		DstIP:    netip.MustParseAddr("10.0.0.5"),
		SrcPort:  45678,
		DstPort:  22,
		Protocol: ProtocolTCP,
		InIface:  "eth0",
		OutIface: "bond0.200",
		Length:   64,
	}

	action, _ := engine.Process(pkt)
	if action != ActionDeny {
		t.Errorf("action: got %v, want deny", action)
	}
	if engine.ConnTrackCount() != 0 {
		t.Errorf("conntrack count: got %d, want 0 (denied packet should not be tracked)", engine.ConnTrackCount())
	}

	stats := engine.Stats()
	if stats.PacketsDenied != 1 {
		t.Errorf("packets denied: got %d, want 1", stats.PacketsDenied)
	}
}

func TestEngine_ProcessDNAT(t *testing.T) {
	engine, err := NewEngine(testConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// DNAT rule matches port 8080 from wan.
	// But wan-to-lan deny rule at priority 50 will deny this since
	// there's no explicit allow rule for DNAT traffic.
	// Add an allow rule for DNAT.
	cfg := testConfig()
	cfg.Rules = append(cfg.Rules, Rule{
		Name:     "allow-dnat-web",
		Priority: 5,
		Action:   ActionAllow,
		Match: RuleMatch{
			SrcZone:  "wan",
			DstPort:  8080,
			Protocol: ProtocolTCP,
		},
	})
	engine, err = NewEngine(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("203.0.113.1"),
		DstIP:    netip.MustParseAddr("23.143.36.1"),
		SrcPort:  45678,
		DstPort:  8080,
		Protocol: ProtocolTCP,
		InIface:  "eth0",
		Length:   64,
	}

	action, natEntry := engine.Process(pkt)
	if action != ActionAllow {
		t.Errorf("action: got %v, want allow", action)
	}
	if natEntry == nil {
		t.Fatal("expected DNAT entry")
	}
	if natEntry.Type != NATTypeDNAT {
		t.Errorf("NAT type: got %v, want DNAT", natEntry.Type)
	}
	if natEntry.TranslatedDst.Addr() != netip.MustParseAddr("10.0.0.10") {
		t.Errorf("translated dst: got %v, want 10.0.0.10", natEntry.TranslatedDst.Addr())
	}
}

func TestEngine_ProcessDefaultDeny(t *testing.T) {
	engine, err := NewEngine(testConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Packet from unknown interface, no zone match, no rule match.
	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("172.16.0.1"),
		DstIP:    netip.MustParseAddr("172.16.0.2"),
		SrcPort:  12345,
		DstPort:  9999,
		Protocol: ProtocolTCP,
		InIface:  "unknown0",
		Length:   64,
	}

	action, _ := engine.Process(pkt)
	if action != ActionDeny {
		t.Errorf("action: got %v, want deny (default policy)", action)
	}
}

func TestEngine_ProcessDefaultAllow(t *testing.T) {
	cfg := testConfig()
	cfg.DefaultPolicy = "allow"
	cfg.Rules = nil // No rules at all.
	engine, err := NewEngine(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("10.0.0.1"),
		DstIP:    netip.MustParseAddr("10.0.0.2"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: ProtocolTCP,
		Length:   64,
	}

	action, _ := engine.Process(pkt)
	if action != ActionAllow {
		t.Errorf("action: got %v, want allow (default policy)", action)
	}
}

func TestEngine_ExpireConnections(t *testing.T) {
	cfg := testConfig()
	cfg.Timeouts = ConnTrackTimeouts{
		TCPEstablished: 50 * time.Millisecond,
		TCPClose:       50 * time.Millisecond,
		UDP:            50 * time.Millisecond,
		ICMP:           50 * time.Millisecond,
	}
	engine, err := NewEngine(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
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
	engine.Process(pkt)

	if engine.ConnTrackCount() != 1 {
		t.Fatalf("conntrack before expire: got %d, want 1", engine.ConnTrackCount())
	}

	// Expire with a future time well past the timeout.
	removed := engine.ExpireConnections(time.Now().Add(time.Second))
	if removed != 1 {
		t.Errorf("expired: got %d, want 1", removed)
	}
	if engine.ConnTrackCount() != 0 {
		t.Errorf("conntrack after expire: got %d, want 0", engine.ConnTrackCount())
	}
}

func TestEngine_ConnTrackSnapshot(t *testing.T) {
	engine, err := NewEngine(testConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	for i := uint16(0); i < 5; i++ {
		pkt := &PacketInfo{
			SrcIP:    netip.MustParseAddr("10.0.0.5"),
			DstIP:    netip.MustParseAddr("8.8.8.8"),
			SrcPort:  45678 + i,
			DstPort:  443,
			Protocol: ProtocolTCP,
			InIface:  "bond0.200",
			OutIface: "eth0",
			Length:   64,
		}
		engine.Process(pkt)
	}

	snap := engine.ConnTrackSnapshot()
	if len(snap) != 5 {
		t.Errorf("snapshot length: got %d, want 5", len(snap))
	}
}

func TestEngine_Stats(t *testing.T) {
	engine, err := NewEngine(testConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Allowed packet.
	engine.Process(&PacketInfo{
		SrcIP:    netip.MustParseAddr("10.0.0.5"),
		DstIP:    netip.MustParseAddr("8.8.8.8"),
		SrcPort:  45678,
		DstPort:  443,
		Protocol: ProtocolTCP,
		InIface:  "bond0.200",
		OutIface: "eth0",
		Length:   64,
	})

	// Denied packet.
	engine.Process(&PacketInfo{
		SrcIP:    netip.MustParseAddr("203.0.113.1"),
		DstIP:    netip.MustParseAddr("10.0.0.5"),
		SrcPort:  45678,
		DstPort:  22,
		Protocol: ProtocolTCP,
		InIface:  "eth0",
		OutIface: "bond0.200",
		Length:   64,
	})

	stats := engine.Stats()
	if stats.PacketsProcessed != 2 {
		t.Errorf("processed: got %d, want 2", stats.PacketsProcessed)
	}
	if stats.PacketsAllowed != 1 {
		t.Errorf("allowed: got %d, want 1", stats.PacketsAllowed)
	}
	if stats.PacketsDenied != 1 {
		t.Errorf("denied: got %d, want 1", stats.PacketsDenied)
	}
}

func TestEngine_RulePriorityOrdering(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: "deny",
		Rules: []Rule{
			{
				Name:     "deny-all",
				Priority: 100,
				Action:   ActionDeny,
				Match:    RuleMatch{},
			},
			{
				Name:     "allow-ssh",
				Priority: 10,
				Action:   ActionAllow,
				Match: RuleMatch{
					DstPort:  22,
					Protocol: ProtocolTCP,
				},
			},
		},
	}
	engine, err := NewEngine(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// SSH packet should be allowed (priority 10 < 100).
	action, _ := engine.Process(&PacketInfo{
		SrcIP:    netip.MustParseAddr("10.0.0.1"),
		DstIP:    netip.MustParseAddr("10.0.0.2"),
		SrcPort:  45678,
		DstPort:  22,
		Protocol: ProtocolTCP,
		Length:   64,
	})
	if action != ActionAllow {
		t.Errorf("SSH action: got %v, want allow", action)
	}

	// HTTP packet should be denied (matches deny-all at priority 100).
	action, _ = engine.Process(&PacketInfo{
		SrcIP:    netip.MustParseAddr("10.0.0.1"),
		DstIP:    netip.MustParseAddr("10.0.0.2"),
		SrcPort:  45679,
		DstPort:  80,
		Protocol: ProtocolTCP,
		Length:   64,
	})
	if action != ActionDeny {
		t.Errorf("HTTP action: got %v, want deny", action)
	}
}

func TestEngine_DNSAllowRule(t *testing.T) {
	engine, err := NewEngine(testConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("10.0.0.5"),
		DstIP:    netip.MustParseAddr("8.8.8.8"),
		SrcPort:  45678,
		DstPort:  53,
		Protocol: ProtocolUDP,
		Length:   64,
	}

	action, _ := engine.Process(pkt)
	if action != ActionAllow {
		t.Errorf("DNS action: got %v, want allow", action)
	}
}

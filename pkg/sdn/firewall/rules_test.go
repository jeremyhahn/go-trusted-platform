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

func TestRule_MatchesExact(t *testing.T) {
	rule := Rule{
		Name:     "allow-ssh",
		Priority: 10,
		Action:   ActionAllow,
		Match: RuleMatch{
			SrcZone:  "lan",
			DstZone:  "wan",
			SrcNet:   netip.MustParsePrefix("10.0.0.0/24"),
			DstNet:   netip.MustParsePrefix("0.0.0.0/0"),
			DstPort:  22,
			Protocol: ProtocolTCP,
		},
	}

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("10.0.0.5"),
		DstIP:    netip.MustParseAddr("8.8.8.8"),
		SrcPort:  45678,
		DstPort:  22,
		Protocol: ProtocolTCP,
		SrcZone:  "lan",
		DstZone:  "wan",
	}

	if !rule.Matches(pkt) {
		t.Error("expected rule to match packet")
	}
}

func TestRule_MatchesWildcard(t *testing.T) {
	rule := Rule{
		Name:     "allow-all",
		Priority: 100,
		Action:   ActionAllow,
		Match:    RuleMatch{},
	}

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("192.168.1.1"),
		DstIP:    netip.MustParseAddr("10.0.0.1"),
		SrcPort:  12345,
		DstPort:  443,
		Protocol: ProtocolTCP,
		SrcZone:  "any",
		DstZone:  "any",
	}

	if !rule.Matches(pkt) {
		t.Error("wildcard rule should match any packet")
	}
}

func TestRule_MatchesSrcZoneMismatch(t *testing.T) {
	rule := Rule{
		Name:   "lan-only",
		Action: ActionAllow,
		Match: RuleMatch{
			SrcZone: "lan",
		},
	}

	pkt := &PacketInfo{
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		DstIP:   netip.MustParseAddr("10.0.0.2"),
		SrcZone: "wan",
	}

	if rule.Matches(pkt) {
		t.Error("rule should not match different source zone")
	}
}

func TestRule_MatchesDstZoneMismatch(t *testing.T) {
	rule := Rule{
		Name:   "to-dmz",
		Action: ActionAllow,
		Match: RuleMatch{
			DstZone: "dmz",
		},
	}

	pkt := &PacketInfo{
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		DstIP:   netip.MustParseAddr("10.0.0.2"),
		DstZone: "lan",
	}

	if rule.Matches(pkt) {
		t.Error("rule should not match different destination zone")
	}
}

func TestRule_MatchesSrcNetMismatch(t *testing.T) {
	rule := Rule{
		Name:   "from-10-net",
		Action: ActionAllow,
		Match: RuleMatch{
			SrcNet: netip.MustParsePrefix("10.0.0.0/8"),
		},
	}

	pkt := &PacketInfo{
		SrcIP: netip.MustParseAddr("192.168.1.1"),
		DstIP: netip.MustParseAddr("10.0.0.2"),
	}

	if rule.Matches(pkt) {
		t.Error("rule should not match source outside network")
	}
}

func TestRule_MatchesDstNetMismatch(t *testing.T) {
	rule := Rule{
		Name:   "to-10-net",
		Action: ActionAllow,
		Match: RuleMatch{
			DstNet: netip.MustParsePrefix("10.0.0.0/8"),
		},
	}

	pkt := &PacketInfo{
		SrcIP: netip.MustParseAddr("10.0.0.1"),
		DstIP: netip.MustParseAddr("192.168.1.1"),
	}

	if rule.Matches(pkt) {
		t.Error("rule should not match destination outside network")
	}
}

func TestRule_MatchesPortMismatch(t *testing.T) {
	rule := Rule{
		Name:   "http-only",
		Action: ActionAllow,
		Match: RuleMatch{
			DstPort: 80,
		},
	}

	pkt := &PacketInfo{
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		DstIP:   netip.MustParseAddr("10.0.0.2"),
		DstPort: 443,
	}

	if rule.Matches(pkt) {
		t.Error("rule should not match different port")
	}
}

func TestRule_MatchesSrcPortMismatch(t *testing.T) {
	rule := Rule{
		Name:   "src-port",
		Action: ActionAllow,
		Match: RuleMatch{
			SrcPort: 5000,
		},
	}

	pkt := &PacketInfo{
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		DstIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 6000,
	}

	if rule.Matches(pkt) {
		t.Error("rule should not match different source port")
	}
}

func TestRule_MatchesProtocolMismatch(t *testing.T) {
	rule := Rule{
		Name:   "tcp-only",
		Action: ActionAllow,
		Match: RuleMatch{
			Protocol: ProtocolTCP,
		},
	}

	pkt := &PacketInfo{
		SrcIP:    netip.MustParseAddr("10.0.0.1"),
		DstIP:    netip.MustParseAddr("10.0.0.2"),
		Protocol: ProtocolUDP,
	}

	if rule.Matches(pkt) {
		t.Error("rule should not match different protocol")
	}
}

func TestRule_MatchesState(t *testing.T) {
	rule := Rule{
		Name:   "established-only",
		Action: ActionAllow,
		Match: RuleMatch{
			State: []ConnState{ConnStateEstablished, ConnStateRelated},
		},
	}

	t.Run("established matches", func(t *testing.T) {
		pkt := &PacketInfo{
			SrcIP:     netip.MustParseAddr("10.0.0.1"),
			DstIP:     netip.MustParseAddr("10.0.0.2"),
			ConnState: ConnStateEstablished,
		}
		if !rule.Matches(pkt) {
			t.Error("expected established state to match")
		}
	})

	t.Run("related matches", func(t *testing.T) {
		pkt := &PacketInfo{
			SrcIP:     netip.MustParseAddr("10.0.0.1"),
			DstIP:     netip.MustParseAddr("10.0.0.2"),
			ConnState: ConnStateRelated,
		}
		if !rule.Matches(pkt) {
			t.Error("expected related state to match")
		}
	})

	t.Run("new does not match", func(t *testing.T) {
		pkt := &PacketInfo{
			SrcIP:     netip.MustParseAddr("10.0.0.1"),
			DstIP:     netip.MustParseAddr("10.0.0.2"),
			ConnState: ConnStateNew,
		}
		if rule.Matches(pkt) {
			t.Error("new state should not match established/related rule")
		}
	})
}

func TestSortRules(t *testing.T) {
	rules := []Rule{
		{Name: "low", Priority: 100},
		{Name: "high", Priority: 1},
		{Name: "mid", Priority: 50},
	}
	sortRules(rules)

	if rules[0].Name != "high" || rules[1].Name != "mid" || rules[2].Name != "low" {
		t.Errorf("sort order wrong: %s, %s, %s", rules[0].Name, rules[1].Name, rules[2].Name)
	}
}

func TestAction_String(t *testing.T) {
	tests := []struct {
		action Action
		want   string
	}{
		{ActionAllow, "allow"},
		{ActionDeny, "deny"},
		{ActionReject, "reject"},
		{Action(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.action.String()
		if got != tt.want {
			t.Errorf("Action(%d).String() = %q, want %q", tt.action, got, tt.want)
		}
	}
}

func TestParseAction(t *testing.T) {
	tests := []struct {
		input string
		want  Action
	}{
		{"allow", ActionAllow},
		{"deny", ActionDeny},
		{"reject", ActionReject},
		{"unknown", ActionDeny},
		{"", ActionDeny},
	}
	for _, tt := range tests {
		got := parseAction(tt.input)
		if got != tt.want {
			t.Errorf("parseAction(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

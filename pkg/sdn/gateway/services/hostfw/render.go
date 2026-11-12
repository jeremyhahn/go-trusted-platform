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

package hostfw

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

// Rendered is one ruleset in both forms the filter needs: the textual
// `.nft` file for the boot window, and the rule list the live applier
// programs over netlink. Fingerprint identifies the ruleset so the
// reconciler can tell an unchanged inventory from a changed one without
// reading the kernel back.
type Rendered struct {
	// Text is the complete `nft -f` file: it replaces the table atomically.
	Text string
	// Rules are the input-chain rules in order, one per rendered line.
	Rules []Rule
	// Fingerprint is the SHA-256 of Text.
	Fingerprint string
	// ICMP is the limit the rules were rendered with.
	ICMP RateLimit
}

// Rule is one accept (or drop) rule of the input chain in structured form.
// The text renderer and the netlink builder both consume it, so the file
// the boot window loads and the table the daemon programs cannot drift.
type Rule struct {
	// Kind classifies the rule; the builder dispatches on it.
	Kind RuleKind
	// Interface scopes the rule to iifname; empty means any.
	Interface string
	// Family is 4 or 6 for address-bearing rules, 0 when family-neutral.
	Family int
	// Protocol is the transport (tcp/udp) for listener rules.
	Protocol Protocol
	// Port is the destination port for listener and tunnel rules.
	Port uint16
	// Source is the source prefix for listener rules with a source set
	// (one rule per prefix); invalid when unrestricted.
	Source netip.Prefix
	// Peer is the peer address for peer allowance rules.
	Peer netip.Addr
	// IPProto is the IP protocol number for peer rules.
	IPProto uint8
	// Comment is the rule comment.
	Comment string
}

// RuleKind is the rule's shape.
type RuleKind int

const (
	// RuleLoopback accepts everything on lo.
	RuleLoopback RuleKind = iota
	// RuleEstablished accepts established and related conntrack states.
	RuleEstablished
	// RuleInvalid drops invalid conntrack states.
	RuleInvalid
	// RuleUnfiltered accepts everything on a deliberately open interface.
	RuleUnfiltered
	// RuleICMPv4 accepts rate-limited ICMP.
	RuleICMPv4
	// RuleICMPv6ND accepts neighbour discovery unconditionally.
	RuleICMPv6ND
	// RuleICMPv6 accepts rate-limited ICMPv6.
	RuleICMPv6
	// RuleListener accepts a transport port, optionally from a source prefix.
	RuleListener
	// RulePeer accepts an IP protocol from one peer address.
	RulePeer
	// RuleTunnelPort accepts BGP/BFD on a tunnel interface.
	RuleTunnelPort
	// RuleVRRP accepts VRRP (IP protocol 112) on an FHRP interface.
	RuleVRRP
)

// Render validates and normalises the ruleset and produces both forms.
func Render(rs Ruleset) (*Rendered, error) {
	if err := rs.Validate(); err != nil {
		return nil, err
	}
	n := rs.normalized()
	rules := compile(n)
	text := renderText(rules, n.ICMP)
	sum := sha256.Sum256([]byte(text))
	return &Rendered{
		Text:        text,
		Rules:       rules,
		Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		ICMP:        n.ICMP,
	}, nil
}

// compile turns the normalised ruleset into the ordered rule list. Order
// is the policy: loopback and conntrack first, the deliberate exceptions,
// ICMP, then the allowlist; the chain policy drops the rest.
func compile(rs Ruleset) []Rule {
	var rules []Rule
	rules = append(rules,
		Rule{Kind: RuleLoopback, Interface: "lo", Comment: "loopback"},
		Rule{Kind: RuleEstablished, Comment: "established/related"},
		Rule{Kind: RuleInvalid, Comment: "invalid"},
	)
	for _, ifc := range rs.Unfiltered {
		rules = append(rules, Rule{Kind: RuleUnfiltered, Interface: ifc, Comment: "unfiltered: " + ifc})
	}
	rules = append(rules,
		Rule{Kind: RuleICMPv4, Comment: "icmp rate-limited"},
		Rule{Kind: RuleICMPv6ND, Comment: "icmpv6 neighbour discovery"},
		Rule{Kind: RuleICMPv6, Comment: "icmpv6 rate-limited"},
	)
	for _, l := range rs.Listeners {
		comment := l.Comment
		if comment == "" {
			comment = fmt.Sprintf("listener %s/%d", l.Protocol, l.Port)
		}
		if len(l.Sources) == 0 {
			rules = append(rules, Rule{Kind: RuleListener, Interface: l.Interface, Protocol: l.Protocol, Port: l.Port, Comment: comment})
			continue
		}
		for _, src := range l.Sources {
			fam := 4
			if src.Addr().Is6() {
				fam = 6
			}
			rules = append(rules, Rule{Kind: RuleListener, Interface: l.Interface, Family: fam, Protocol: l.Protocol, Port: l.Port, Source: src.Masked(), Comment: comment})
		}
	}
	for _, p := range rs.Peers {
		proto := ipProtoESP
		if p.Protocol == PeerProtocolGRE {
			proto = ipProtoGRE
		}
		for _, a := range p.Addresses {
			fam := 4
			if a.Is6() {
				fam = 6
			}
			rules = append(rules, Rule{Kind: RulePeer, Interface: p.Interface, Family: fam, Peer: a, IPProto: proto,
				Comment: fmt.Sprintf("peer %s %s", p.Protocol, a)})
		}
	}
	for _, t := range rs.Tunnels {
		rules = append(rules,
			Rule{Kind: RuleTunnelPort, Interface: t, Protocol: ProtocolTCP, Port: PortBGP, Comment: "bgp on " + t},
			Rule{Kind: RuleTunnelPort, Interface: t, Protocol: ProtocolUDP, Port: PortBFD, Comment: "bfd on " + t},
		)
	}
	for _, ifc := range rs.VRRP {
		rules = append(rules, Rule{Kind: RuleVRRP, Interface: ifc, IPProto: ipProtoVRRP, Comment: "vrrp on " + ifc})
	}
	return rules
}

// renderText writes the `nft -f` form. The file deletes and recreates the
// table inside one transaction, which is how nft(8) replaces a table
// atomically; the leading `table` declaration makes the delete succeed on a
// host where the table does not exist yet.
func renderText(rules []Rule, icmp RateLimit) string {
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# go-trusted-platform hostfw — rendered; do not edit, the daemon reconciles it.\n")
	fmt.Fprintf(&b, "table inet %s\n", TableName)
	fmt.Fprintf(&b, "delete table inet %s\n", TableName)
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	fmt.Fprintf(&b, "\tchain %s {\n", ChainInput)
	b.WriteString("\t\ttype filter hook input priority filter; policy drop;\n")
	for _, r := range rules {
		b.WriteString("\t\t")
		b.WriteString(ruleText(r, icmp))
		b.WriteString("\n")
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

func ruleText(r Rule, icmp RateLimit) string {
	var parts []string
	if r.Interface != "" {
		parts = append(parts, fmt.Sprintf("iifname %q", r.Interface))
	}
	switch r.Kind {
	case RuleLoopback, RuleUnfiltered:
		parts = append(parts, "accept")
	case RuleEstablished:
		// GRE and ESP are admitted only by a peer allowance: once the host
		// has sent either to an address, conntrack calls that address's
		// packets established, whether or not it is a declared peer.
		parts = append(parts, "meta l4proto != { gre, esp } ct state established,related accept")
	case RuleInvalid:
		parts = append(parts, "ct state invalid drop")
	case RuleICMPv4:
		parts = append(parts, fmt.Sprintf("meta l4proto icmp limit rate %d/second burst %d packets accept", icmp.Rate, icmp.Burst))
	case RuleICMPv6ND:
		parts = append(parts, "meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect } accept")
	case RuleICMPv6:
		parts = append(parts, fmt.Sprintf("meta l4proto ipv6-icmp limit rate %d/second burst %d packets accept", icmp.Rate, icmp.Burst))
	case RuleListener, RuleTunnelPort:
		if r.Source.IsValid() {
			parts = append(parts, fmt.Sprintf("%s saddr %s", familyKeyword(r.Family), r.Source))
		}
		parts = append(parts, fmt.Sprintf("%s dport %d accept", r.Protocol, r.Port))
	case RulePeer:
		name := "esp"
		if r.IPProto == ipProtoGRE {
			name = "gre"
		}
		parts = append(parts, fmt.Sprintf("%s saddr %s meta l4proto %s accept", familyKeyword(r.Family), r.Peer, name))
	case RuleVRRP:
		// Numeric, so the boot-time nft -f does not depend on /etc/protocols.
		parts = append(parts, "meta l4proto 112 accept")
	}
	return strings.Join(parts, " ") + fmt.Sprintf(" comment %q", r.Comment)
}

func familyKeyword(family int) string {
	if family == 6 {
		return "ip6"
	}
	return "ip"
}

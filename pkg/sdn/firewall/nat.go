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
	"log/slog"
	"net/netip"
)

// NATType identifies the direction of address translation.
type NATType uint8

const (
	// NATTypeSNAT rewrites the source address (masquerade).
	NATTypeSNAT NATType = iota

	// NATTypeDNAT rewrites the destination address (port forward).
	NATTypeDNAT
)

// String returns the human-readable name of the NAT type.
func (t NATType) String() string {
	name, ok := natTypeNames[t]
	if !ok {
		return "unknown"
	}
	return name
}

var natTypeNames = map[NATType]string{
	NATTypeSNAT: "SNAT",
	NATTypeDNAT: "DNAT",
}

// NATRule defines a network address translation rule.
type NATRule struct {
	// Name is the human-readable rule identifier.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// Type is the NAT direction (SNAT or DNAT).
	Type NATType `yaml:"type" json:"type" mapstructure:"type"`

	// FromZone is the source zone. Empty matches any zone.
	FromZone string `yaml:"from-zone,omitempty" json:"from_zone,omitempty" mapstructure:"from-zone"`

	// ToZone is the destination zone. Empty matches any zone.
	ToZone string `yaml:"to-zone,omitempty" json:"to_zone,omitempty" mapstructure:"to-zone"`

	// DstPort is the original destination port for DNAT matching.
	DstPort uint16 `yaml:"dst-port,omitempty" json:"dst_port,omitempty" mapstructure:"dst-port"`

	// TargetIP is the translated destination IP for DNAT.
	TargetIP netip.Addr `yaml:"target-ip,omitempty" json:"target_ip,omitempty" mapstructure:"target-ip"`

	// TargetPort is the translated destination port for DNAT.
	TargetPort uint16 `yaml:"target-port,omitempty" json:"target_port,omitempty" mapstructure:"target-port"`

	// Protocol is the IP protocol number. Zero matches any protocol.
	Protocol uint8 `yaml:"protocol,omitempty" json:"protocol,omitempty" mapstructure:"protocol"`

	// Masquerade indicates SNAT should use the outgoing interface IP.
	Masquerade bool `yaml:"masquerade,omitempty" json:"masquerade,omitempty" mapstructure:"masquerade"`
}

// NATEntry holds the translation state for a NATted connection.
type NATEntry struct {
	// Type identifies the NAT direction.
	Type NATType

	// OriginalSrc is the original source address and port.
	OriginalSrc netip.AddrPort

	// OriginalDst is the original destination address and port.
	OriginalDst netip.AddrPort

	// TranslatedSrc is the translated source address and port.
	TranslatedSrc netip.AddrPort

	// TranslatedDst is the translated destination address and port.
	TranslatedDst netip.AddrPort
}

// NATEngine evaluates NAT rules against packets and produces translation entries.
type NATEngine struct {
	snatRules []NATRule
	dnatRules []NATRule
	logger    *slog.Logger
}

// NewNATEngine creates a NAT engine from the given rules.
func NewNATEngine(rules []NATRule, logger *slog.Logger) *NATEngine {
	var snat, dnat []NATRule
	for i := range rules {
		switch rules[i].Type {
		case NATTypeSNAT:
			snat = append(snat, rules[i])
		case NATTypeDNAT:
			dnat = append(dnat, rules[i])
		}
	}
	return &NATEngine{
		snatRules: snat,
		dnatRules: dnat,
		logger:    logger,
	}
}

// Apply evaluates NAT rules against the packet and returns a translation
// entry if a rule matches. Returns nil if no NAT applies.
func (n *NATEngine) Apply(pkt *PacketInfo, direction Direction) *NATEntry {
	if direction == DirectionIngress {
		return n.applyDNAT(pkt)
	}
	return n.applySNAT(pkt)
}

// applyDNAT checks DNAT rules for inbound packets.
func (n *NATEngine) applyDNAT(pkt *PacketInfo) *NATEntry {
	for i := range n.dnatRules {
		rule := &n.dnatRules[i]
		if !n.matchesNATRule(rule, pkt) {
			continue
		}
		return &NATEntry{
			Type:          NATTypeDNAT,
			OriginalSrc:   netip.AddrPortFrom(pkt.SrcIP, pkt.SrcPort),
			OriginalDst:   netip.AddrPortFrom(pkt.DstIP, pkt.DstPort),
			TranslatedSrc: netip.AddrPortFrom(pkt.SrcIP, pkt.SrcPort),
			TranslatedDst: netip.AddrPortFrom(rule.TargetIP, rule.TargetPort),
		}
	}
	return nil
}

// applySNAT checks SNAT rules for outbound packets.
func (n *NATEngine) applySNAT(pkt *PacketInfo) *NATEntry {
	for i := range n.snatRules {
		rule := &n.snatRules[i]
		if !n.matchesNATRule(rule, pkt) {
			continue
		}
		// For masquerade, the actual translated source IP must be
		// provided by the caller (the outgoing interface IP). We use
		// the destination IP as a placeholder; the packet rewriter
		// fills in the real address.
		translatedSrc := pkt.SrcIP
		if rule.Masquerade {
			// Masquerade: translated source will be set by the packet
			// path using the outgoing interface address. We mark it
			// with an invalid addr to signal masquerade mode.
			translatedSrc = netip.Addr{}
		}
		return &NATEntry{
			Type:          NATTypeSNAT,
			OriginalSrc:   netip.AddrPortFrom(pkt.SrcIP, pkt.SrcPort),
			OriginalDst:   netip.AddrPortFrom(pkt.DstIP, pkt.DstPort),
			TranslatedSrc: netip.AddrPortFrom(translatedSrc, pkt.SrcPort),
			TranslatedDst: netip.AddrPortFrom(pkt.DstIP, pkt.DstPort),
		}
	}
	return nil
}

// matchesNATRule checks if a packet matches a NAT rule's criteria.
func (n *NATEngine) matchesNATRule(rule *NATRule, pkt *PacketInfo) bool {
	if rule.FromZone != "" && rule.FromZone != pkt.SrcZone {
		return false
	}
	if rule.ToZone != "" && rule.ToZone != pkt.DstZone {
		return false
	}
	if rule.Protocol != 0 && rule.Protocol != pkt.Protocol {
		return false
	}
	if rule.DstPort != 0 && rule.DstPort != pkt.DstPort {
		return false
	}
	return true
}

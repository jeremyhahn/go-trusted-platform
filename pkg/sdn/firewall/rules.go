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
	"sort"
)

// Action is the firewall verdict for a packet.
type Action uint8

const (
	// ActionAllow permits the packet.
	ActionAllow Action = iota

	// ActionDeny silently drops the packet.
	ActionDeny

	// ActionReject drops the packet and sends an ICMP unreachable.
	ActionReject
)

// String returns the human-readable name of the action.
func (a Action) String() string {
	name, ok := actionNames[a]
	if !ok {
		return "unknown"
	}
	return name
}

var actionNames = map[Action]string{
	ActionAllow:  "allow",
	ActionDeny:   "deny",
	ActionReject: "reject",
}

// parseAction converts a string to an Action.
func parseAction(s string) Action {
	a, ok := actionParse[s]
	if !ok {
		return ActionDeny
	}
	return a
}

var actionParse = map[string]Action{
	"allow":  ActionAllow,
	"deny":   ActionDeny,
	"reject": ActionReject,
}

// Rule defines a single firewall rule with match criteria and an action.
type Rule struct {
	// Name is the human-readable rule identifier.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// Priority controls evaluation order; lower values are evaluated first.
	Priority int `yaml:"priority" json:"priority" mapstructure:"priority"`

	// Action is the verdict when this rule matches.
	Action Action `yaml:"action" json:"action" mapstructure:"action"`

	// Match specifies the packet match criteria.
	Match RuleMatch `yaml:"match" json:"match" mapstructure:"match"`
}

// RuleMatch specifies the criteria for matching a packet.
type RuleMatch struct {
	// SrcZone is the source zone name. Empty matches any zone.
	SrcZone string `yaml:"src-zone,omitempty" json:"src_zone,omitempty" mapstructure:"src-zone"`

	// DstZone is the destination zone name. Empty matches any zone.
	DstZone string `yaml:"dst-zone,omitempty" json:"dst_zone,omitempty" mapstructure:"dst-zone"`

	// SrcNet is the source network prefix. Zero value matches any source.
	SrcNet netip.Prefix `yaml:"src-net,omitempty" json:"src_net,omitempty" mapstructure:"src-net"`

	// DstNet is the destination network prefix. Zero value matches any destination.
	DstNet netip.Prefix `yaml:"dst-net,omitempty" json:"dst_net,omitempty" mapstructure:"dst-net"`

	// SrcPort is the source port. Zero matches any port.
	SrcPort uint16 `yaml:"src-port,omitempty" json:"src_port,omitempty" mapstructure:"src-port"`

	// DstPort is the destination port. Zero matches any port.
	DstPort uint16 `yaml:"dst-port,omitempty" json:"dst_port,omitempty" mapstructure:"dst-port"`

	// Protocol is the IP protocol number. Zero matches any protocol.
	Protocol uint8 `yaml:"protocol,omitempty" json:"protocol,omitempty" mapstructure:"protocol"`

	// State limits matching to specific connection states. Empty matches any state.
	State []ConnState `yaml:"state,omitempty" json:"state,omitempty" mapstructure:"state"`
}

// Matches reports whether the rule matches the given packet and its
// resolved zone context.
func (r *Rule) Matches(pkt *PacketInfo) bool {
	m := &r.Match

	if m.SrcZone != "" && m.SrcZone != pkt.SrcZone {
		return false
	}
	if m.DstZone != "" && m.DstZone != pkt.DstZone {
		return false
	}
	if m.SrcNet.IsValid() && !m.SrcNet.Contains(pkt.SrcIP) {
		return false
	}
	if m.DstNet.IsValid() && !m.DstNet.Contains(pkt.DstIP) {
		return false
	}
	if m.SrcPort != 0 && m.SrcPort != pkt.SrcPort {
		return false
	}
	if m.DstPort != 0 && m.DstPort != pkt.DstPort {
		return false
	}
	if m.Protocol != 0 && m.Protocol != pkt.Protocol {
		return false
	}
	if len(m.State) > 0 {
		matched := false
		for _, s := range m.State {
			if s == pkt.ConnState {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// sortRules sorts rules by priority (ascending) for evaluation order.
func sortRules(rules []Rule) {
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})
}

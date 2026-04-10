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

package policy

import (
	"fmt"
	"strings"
)

// RuleGenerator generates OpenFlow rules from policy
type RuleGenerator struct {
	// DefaultTable is the default flow table to use
	DefaultTable int

	// BasePriority is the base priority for generated rules
	BasePriority int
}

// NewRuleGenerator creates a new rule generator
func NewRuleGenerator() *RuleGenerator {
	return &RuleGenerator{
		DefaultTable: 0,
		BasePriority: 1000,
	}
}

// GenerateAuthorizationRules generates OpenFlow rules for an authorized port
func (g *RuleGenerator) GenerateAuthorizationRules(portID string, policy *PortPolicy) ([]FlowRule, error) {
	if policy == nil {
		return nil, ErrInvalidPolicy
	}

	var rules []FlowRule

	// Generate VLAN tagging rule
	if policy.VLAN > 0 {
		vlanRule := g.generateVLANRule(portID, policy.VLAN)
		rules = append(rules, vlanRule)
	}

	// Generate ACL rules
	for _, acl := range policy.ACLs {
		aclRule := g.generateACLRule(portID, policy.VLAN, acl)
		rules = append(rules, aclRule)
	}

	// If no ACL rules, add default allow rule
	if len(policy.ACLs) == 0 {
		defaultRule := g.generateDefaultAllowRule(portID, policy.VLAN)
		rules = append(rules, defaultRule)
	}

	return rules, nil
}

// GenerateBlockRules generates OpenFlow rules to block a port
func (g *RuleGenerator) GenerateBlockRules(portID string) []FlowRule {
	return []FlowRule{
		{
			Table:    g.DefaultTable,
			Priority: g.BasePriority + 1000, // High priority to override other rules
			Match:    g.buildMatch(FlowMatch{InPort: portID}),
			Actions:  "drop",
		},
	}
}

// GenerateUnauthorizedRules generates OpenFlow rules for unauthorized ports
func (g *RuleGenerator) GenerateUnauthorizedRules(portID string) []FlowRule {
	return []FlowRule{
		{
			Table:    g.DefaultTable,
			Priority: g.BasePriority + 500,
			Match:    g.buildMatch(FlowMatch{InPort: portID}),
			Actions:  "drop",
		},
	}
}

// generateVLANRule creates a VLAN tagging rule
func (g *RuleGenerator) generateVLANRule(portID string, vlan uint16) FlowRule {
	match := g.buildMatch(FlowMatch{InPort: portID})
	actions := fmt.Sprintf("mod_vlan_vid:%d,normal", vlan)

	return FlowRule{
		Table:    g.DefaultTable,
		Priority: g.BasePriority + 100,
		Match:    match,
		Actions:  actions,
	}
}

// generateACLRule creates an ACL flow rule
func (g *RuleGenerator) generateACLRule(portID string, vlan uint16, acl ACLRule) FlowRule {
	// Combine port and ACL match criteria
	match := acl.Match
	match.InPort = portID
	if vlan > 0 {
		match.VLANVid = vlan
	}

	matchStr := g.buildMatch(match)
	actionsStr := g.buildActions(acl.Action)

	return FlowRule{
		Table:    g.DefaultTable,
		Priority: g.BasePriority + acl.Priority,
		Match:    matchStr,
		Actions:  actionsStr,
	}
}

// generateDefaultAllowRule creates a default allow rule
func (g *RuleGenerator) generateDefaultAllowRule(portID string, vlan uint16) FlowRule {
	match := FlowMatch{
		InPort:  portID,
		VLANVid: vlan,
	}

	return FlowRule{
		Table:    g.DefaultTable,
		Priority: g.BasePriority,
		Match:    g.buildMatch(match),
		Actions:  "normal",
	}
}

// buildMatch constructs an OpenFlow match string
func (g *RuleGenerator) buildMatch(match FlowMatch) string {
	var parts []string

	if match.InPort != "" {
		parts = append(parts, fmt.Sprintf("in_port=%s", match.InPort))
	}

	if match.EthSrc != "" {
		parts = append(parts, fmt.Sprintf("dl_src=%s", match.EthSrc))
	}

	if match.EthDst != "" {
		parts = append(parts, fmt.Sprintf("dl_dst=%s", match.EthDst))
	}

	if match.EthType > 0 {
		parts = append(parts, fmt.Sprintf("dl_type=0x%04x", match.EthType))
	}

	if match.VLANVid > 0 {
		parts = append(parts, fmt.Sprintf("dl_vlan=%d", match.VLANVid))
	}

	if match.IPProto > 0 {
		parts = append(parts, fmt.Sprintf("nw_proto=%d", match.IPProto))
	}

	if match.IPv4Src != "" {
		parts = append(parts, fmt.Sprintf("nw_src=%s", match.IPv4Src))
	}

	if match.IPv4Dst != "" {
		parts = append(parts, fmt.Sprintf("nw_dst=%s", match.IPv4Dst))
	}

	if match.TCPSrc > 0 {
		parts = append(parts, fmt.Sprintf("tp_src=%d", match.TCPSrc))
	}

	if match.TCPDst > 0 {
		parts = append(parts, fmt.Sprintf("tp_dst=%d", match.TCPDst))
	}

	if match.UDPSrc > 0 {
		parts = append(parts, fmt.Sprintf("tp_src=%d", match.UDPSrc))
	}

	if match.UDPDst > 0 {
		parts = append(parts, fmt.Sprintf("tp_dst=%d", match.UDPDst))
	}

	return strings.Join(parts, ",")
}

// buildActions constructs an OpenFlow actions string
func (g *RuleGenerator) buildActions(action FlowAction) string {
	switch action.Type {
	case FlowActionAllow:
		if action.SetVLAN > 0 {
			return fmt.Sprintf("mod_vlan_vid:%d,normal", action.SetVLAN)
		}
		return "normal"

	case FlowActionDeny:
		return "drop"

	case FlowActionForward:
		if action.Output != "" {
			if action.SetVLAN > 0 {
				return fmt.Sprintf("mod_vlan_vid:%d,output:%s", action.SetVLAN, action.Output)
			}
			return fmt.Sprintf("output:%s", action.Output)
		}
		return "drop"

	case FlowActionNormal:
		return "normal"

	default:
		return "drop"
	}
}

// FlowRule represents a complete OpenFlow rule
type FlowRule struct {
	Table    int
	Priority int
	Match    string
	Actions  string
	Cookie   string
}

// String returns the OpenFlow command string for this rule
func (r FlowRule) String() string {
	parts := []string{
		fmt.Sprintf("table=%d", r.Table),
		fmt.Sprintf("priority=%d", r.Priority),
	}

	if r.Match != "" {
		parts = append(parts, r.Match)
	}

	if r.Cookie != "" {
		parts = append(parts, fmt.Sprintf("cookie=%s", r.Cookie))
	}

	parts = append(parts, fmt.Sprintf("actions=%s", r.Actions))

	return strings.Join(parts, ",")
}

// MatchString returns just the match portion for deletion
func (r FlowRule) MatchString() string {
	parts := []string{
		fmt.Sprintf("table=%d", r.Table),
	}

	if r.Match != "" {
		parts = append(parts, r.Match)
	}

	return strings.Join(parts, ",")
}

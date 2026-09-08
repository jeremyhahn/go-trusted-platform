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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/stretchr/testify/require"
)

func TestNewRuleGenerator(t *testing.T) {
	gen := NewRuleGenerator()
	assert.NotNil(t, gen)
	assert.Equal(t, 0, gen.DefaultTable)
	assert.Equal(t, 1000, gen.BasePriority)
}

func TestRuleGenerator_GenerateAuthorizationRules(t *testing.T) {
	gen := NewRuleGenerator()

	t.Run("Nil policy", func(t *testing.T) {
		_, err := gen.GenerateAuthorizationRules("port1", nil)
		assert.ErrorIs(t, err, ErrInvalidPolicy)
	})

	t.Run("Policy with VLAN only", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}

		rules, err := gen.GenerateAuthorizationRules("port1", policy)
		assert.NoError(t, err)
		assert.Len(t, rules, 2) // VLAN rule + default allow

		// Check VLAN rule
		assert.Contains(t, rules[0].Match, "in_port=port1")
		assert.Contains(t, rules[0].Actions, "mod_vlan_vid:100")
	})

	t.Run("Policy with ACLs", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
			ACLs: []ACLRule{
				{
					Priority: 100,
					Match: FlowMatch{
						IPProto: 6,
						TCPDst:  443,
					},
					Action: FlowAction{
						Type: FlowActionAllow,
					},
				},
			},
		}

		rules, err := gen.GenerateAuthorizationRules("port1", policy)
		assert.NoError(t, err)
		assert.Len(t, rules, 2) // VLAN rule + ACL rule

		// Check ACL rule
		assert.Contains(t, rules[1].Match, "in_port=port1")
		assert.Contains(t, rules[1].Match, "nw_proto=6")
		assert.Contains(t, rules[1].Match, "tp_dst=443")
	})

	t.Run("Policy without VLAN", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     0,
		}

		rules, err := gen.GenerateAuthorizationRules("port1", policy)
		assert.NoError(t, err)
		assert.NotEmpty(t, rules)
	})
}

func TestRuleGenerator_GenerateBlockRules(t *testing.T) {
	gen := NewRuleGenerator()

	rules := gen.GenerateBlockRules("port1")
	assert.Len(t, rules, 1)

	rule := rules[0]
	assert.Equal(t, gen.DefaultTable, rule.Table)
	assert.Greater(t, rule.Priority, gen.BasePriority)
	assert.Contains(t, rule.Match, "in_port=port1")
	assert.Equal(t, "drop", rule.Actions)
}

func TestRuleGenerator_GenerateUnauthorizedRules(t *testing.T) {
	gen := NewRuleGenerator()

	rules := gen.GenerateUnauthorizedRules("port1")
	assert.Len(t, rules, 1)

	rule := rules[0]
	assert.Equal(t, gen.DefaultTable, rule.Table)
	assert.Contains(t, rule.Match, "in_port=port1")
	assert.Equal(t, "drop", rule.Actions)
}

func TestRuleGenerator_BuildMatch(t *testing.T) {
	gen := NewRuleGenerator()

	tests := []struct {
		name     string
		match    FlowMatch
		expected []string // Must contain these strings
	}{
		{
			name: "InPort only",
			match: FlowMatch{
				InPort: "port1",
			},
			expected: []string{"in_port=port1"},
		},
		{
			name: "Ethernet match",
			match: FlowMatch{
				EthSrc: "00:11:22:33:44:55",
				EthDst: "66:77:88:99:aa:bb",
			},
			expected: []string{
				"dl_src=00:11:22:33:44:55",
				"dl_dst=66:77:88:99:aa:bb",
			},
		},
		{
			name: "IPv6 addresses render as ipv6_src and ipv6_dst",
			match: FlowMatch{
				EthType: 0x86dd,
				IPv6Src: "2001:db8:1::/64",
				IPv6Dst: "2001:db8:2::1/128",
			},
			expected: []string{
				"dl_type=0x86dd",
				"ipv6_src=2001:db8:1::/64",
				"ipv6_dst=2001:db8:2::1/128",
			},
		},
		{
			name: "VLAN match",
			match: FlowMatch{
				VLANVid: 100,
			},
			expected: []string{"dl_vlan=100"},
		},
		{
			name: "IP proto match",
			match: FlowMatch{
				IPProto: 6,
			},
			expected: []string{"nw_proto=6"},
		},
		{
			name: "IP addresses",
			match: FlowMatch{
				IPv4Src: "10.0.0.1/24",
				IPv4Dst: "192.168.1.0/24",
			},
			expected: []string{
				"nw_src=10.0.0.1/24",
				"nw_dst=192.168.1.0/24",
			},
		},
		{
			name: "TCP ports",
			match: FlowMatch{
				TCPSrc: 8080,
				TCPDst: 443,
			},
			expected: []string{
				"tp_src=8080",
				"tp_dst=443",
			},
		},
		{
			name: "UDP ports",
			match: FlowMatch{
				UDPSrc: 53,
				UDPDst: 5353,
			},
			expected: []string{
				"tp_src=53",
				"tp_dst=5353",
			},
		},
		{
			name: "Complete match",
			match: FlowMatch{
				InPort:  "port1",
				EthType: 0x0800,
				VLANVid: 100,
				IPProto: 6,
				IPv4Src: "10.0.0.1",
				IPv4Dst: "10.0.0.2",
				TCPSrc:  8080,
				TCPDst:  443,
			},
			expected: []string{
				"in_port=port1",
				"dl_type=0x0800",
				"dl_vlan=100",
				"nw_proto=6",
				"nw_src=10.0.0.1",
				"nw_dst=10.0.0.2",
				"tp_src=8080",
				"tp_dst=443",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gen.buildMatch(tt.match)
			for _, exp := range tt.expected {
				assert.Contains(t, result, exp)
			}
		})
	}
}

func TestRuleGenerator_BuildActions(t *testing.T) {
	gen := NewRuleGenerator()

	tests := []struct {
		name     string
		action   FlowAction
		expected string
	}{
		{
			name: "Allow",
			action: FlowAction{
				Type: FlowActionAllow,
			},
			expected: "normal",
		},
		{
			name: "Allow with VLAN",
			action: FlowAction{
				Type:    FlowActionAllow,
				SetVLAN: 100,
			},
			expected: "mod_vlan_vid:100,normal",
		},
		{
			name: "Deny",
			action: FlowAction{
				Type: FlowActionDeny,
			},
			expected: "drop",
		},
		{
			name: "Forward",
			action: FlowAction{
				Type:   FlowActionForward,
				Output: "port2",
			},
			expected: "output:port2",
		},
		{
			name: "Forward with VLAN",
			action: FlowAction{
				Type:    FlowActionForward,
				Output:  "port2",
				SetVLAN: 200,
			},
			expected: "mod_vlan_vid:200,output:port2",
		},
		{
			name: "Forward without output",
			action: FlowAction{
				Type: FlowActionForward,
			},
			expected: "drop",
		},
		{
			name: "Normal",
			action: FlowAction{
				Type: FlowActionNormal,
			},
			expected: "normal",
		},
		{
			name: "Unknown action",
			action: FlowAction{
				Type: FlowActionType("unknown"),
			},
			expected: "drop",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gen.buildActions(tt.action)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFlowRule_String(t *testing.T) {
	tests := []struct {
		name     string
		rule     FlowRule
		contains []string
	}{
		{
			name: "Complete rule",
			rule: FlowRule{
				Table:    0,
				Priority: 100,
				Match:    "in_port=port1",
				Actions:  "normal",
				Cookie:   "0x1234",
			},
			contains: []string{
				"table=0",
				"priority=100",
				"in_port=port1",
				"cookie=0x1234",
				"actions=normal",
			},
		},
		{
			name: "Rule without cookie",
			rule: FlowRule{
				Table:    1,
				Priority: 200,
				Match:    "dl_vlan=100",
				Actions:  "drop",
			},
			contains: []string{
				"table=1",
				"priority=200",
				"dl_vlan=100",
				"actions=drop",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.String()
			for _, s := range tt.contains {
				assert.Contains(t, result, s)
			}
		})
	}
}

func TestFlowRule_MatchString(t *testing.T) {
	rule := FlowRule{
		Table:    0,
		Priority: 100,
		Match:    "in_port=port1,dl_vlan=100",
		Actions:  "normal",
		Cookie:   "0x1234",
	}

	result := rule.MatchString()
	assert.Contains(t, result, "table=0")
	assert.Contains(t, result, "in_port=port1")
	assert.Contains(t, result, "dl_vlan=100")
	assert.NotContains(t, result, "actions")
	assert.NotContains(t, result, "cookie")
}

func TestRuleGenerator_ComplexScenarios(t *testing.T) {
	gen := NewRuleGenerator()

	t.Run("Multi-ACL policy", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
			ACLs: []ACLRule{
				{
					Priority:    200,
					Description: "Allow HTTPS",
					Match: FlowMatch{
						IPProto: 6,
						TCPDst:  443,
					},
					Action: FlowAction{
						Type: FlowActionAllow,
					},
				},
				{
					Priority:    150,
					Description: "Allow DNS",
					Match: FlowMatch{
						IPProto: 17,
						UDPDst:  53,
					},
					Action: FlowAction{
						Type: FlowActionAllow,
					},
				},
				{
					Priority:    100,
					Description: "Deny all else",
					Match:       FlowMatch{},
					Action: FlowAction{
						Type: FlowActionDeny,
					},
				},
			},
		}

		rules, err := gen.GenerateAuthorizationRules("port1", policy)
		require.NoError(t, err)
		assert.Len(t, rules, 4) // VLAN + 3 ACLs

		// Verify priorities are correct
		priorities := make([]int, len(rules))
		for i, rule := range rules {
			priorities[i] = rule.Priority
		}

		// Check that rules include expected priorities
		assert.Contains(t, priorities, gen.BasePriority+100)
		assert.Contains(t, priorities, gen.BasePriority+200)
		assert.Contains(t, priorities, gen.BasePriority+150)
	})

	t.Run("VLAN isolation", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-isolated",
			VLAN:     999,
			ACLs: []ACLRule{
				{
					Priority: 100,
					Match: FlowMatch{
						VLANVid: 999,
					},
					Action: FlowAction{
						Type: FlowActionNormal,
					},
				},
			},
		}

		rules, err := gen.GenerateAuthorizationRules("port1", policy)
		require.NoError(t, err)

		// Verify VLAN is set in rules
		foundVLAN := false
		for _, rule := range rules {
			if strings.Contains(rule.Actions, "mod_vlan_vid:999") ||
				strings.Contains(rule.Match, "dl_vlan=999") {
				foundVLAN = true
				break
			}
		}
		assert.True(t, foundVLAN, "VLAN should be present in rules")
	})
}

// TestRuleGenerator_Terminal pins #567: the generator's allow rules end in
// the configured terminal, and drops are unaffected.
func TestRuleGenerator_Terminal(t *testing.T) {
	g := newRuleGeneratorWithTerminal(zoneflows.TerminalGatewayPipeline)
	assert.Equal(t, "goto_table:10", g.generateDefaultAllowRule("port-1", 200).Actions)
	assert.Equal(t, "goto_table:10", g.buildActions(FlowAction{Type: FlowActionAllow}))
	assert.Equal(t, "mod_vlan_vid:7,goto_table:10", g.buildActions(FlowAction{Type: FlowActionAllow, SetVLAN: 7}))
	assert.Equal(t, "mod_vlan_vid:200,goto_table:10", g.generateVLANRule("port-1", 200).Actions,
		"the VLAN rule outranks the ACL rules of the same policy, so it must take the same terminal")
	assert.Equal(t, "goto_table:10", g.buildActions(FlowAction{Type: FlowActionNormal}))
	assert.Equal(t, "drop", g.buildActions(FlowAction{Type: FlowActionDeny}))

	plain := NewRuleGenerator()
	assert.Equal(t, "normal", plain.generateDefaultAllowRule("port-1", 200).Actions)
	assert.Equal(t, "normal", plain.buildActions(FlowAction{Type: FlowActionAllow}))
}

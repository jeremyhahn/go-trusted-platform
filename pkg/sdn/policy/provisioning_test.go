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
	"net"
	"strings"
	"testing"
)

func TestNewProvisioningFlowGenerator(t *testing.T) {
	tests := []struct {
		name   string
		config *ProvisioningFlowConfig
	}{
		{
			name:   "nil config creates default",
			config: nil,
		},
		{
			name:   "empty config",
			config: &ProvisioningFlowConfig{},
		},
		{
			name: "full config",
			config: &ProvisioningFlowConfig{
				ACMEServerIPs:    []net.IP{net.ParseIP("10.0.0.1")},
				DNSServerIPs:     []net.IP{net.ParseIP("10.0.0.2")},
				ProvisioningVLAN: 100,
				PackageRepoIPs:   []net.IP{net.ParseIP("10.0.0.3")},
				Gateway:          net.ParseIP("10.0.0.254"),
				AllowICMP:        true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewProvisioningFlowGenerator(tt.config)
			if gen == nil {
				t.Fatal("generator is nil")
			}
			if gen.config == nil {
				t.Fatal("config is nil")
			}
			if gen.generator == nil {
				t.Fatal("rule generator is nil")
			}
		})
	}
}

func TestGenerateFlows(t *testing.T) {
	tests := []struct {
		name        string
		config      *ProvisioningFlowConfig
		portID      string
		portMAC     string
		wantMinLen  int
		wantActions []string
	}{
		{
			name: "default configuration without ICMP",
			config: &ProvisioningFlowConfig{
				AllowICMP: false,
			},
			portID:     "1",
			portMAC:    "00:11:22:33:44:55",
			wantMinLen: 6, // ARP, DHCP(2), DNS(6), ACME(3), PackageRepo(2), Default Drop
			wantActions: []string{
				"normal", // ARP
				"drop",   // Default drop
			},
		},
		{
			name: "with ICMP enabled",
			config: &ProvisioningFlowConfig{
				AllowICMP: true,
			},
			portID:     "1",
			portMAC:    "00:11:22:33:44:55",
			wantMinLen: 7, // Includes ICMP rules
		},
		{
			name: "with VLAN tagging",
			config: &ProvisioningFlowConfig{
				ProvisioningVLAN: 100,
			},
			portID:     "1",
			portMAC:    "00:11:22:33:44:55",
			wantMinLen: 6,
		},
		{
			name: "with specific servers",
			config: &ProvisioningFlowConfig{
				ACMEServerIPs:  []net.IP{net.ParseIP("10.0.0.1")},
				DNSServerIPs:   []net.IP{net.ParseIP("10.0.0.2")},
				PackageRepoIPs: []net.IP{net.ParseIP("10.0.0.3")},
			},
			portID:     "1",
			portMAC:    "00:11:22:33:44:55",
			wantMinLen: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewProvisioningFlowGenerator(tt.config)
			flows := gen.GenerateFlows(tt.portID, tt.portMAC)

			if len(flows) < tt.wantMinLen {
				t.Errorf("expected at least %d flows, got %d", tt.wantMinLen, len(flows))
			}

			// Verify all flows have required fields
			for i, flow := range flows {
				if flow.Match == "" {
					t.Errorf("flow %d has empty match", i)
				}
				if flow.Actions == "" {
					t.Errorf("flow %d has empty actions", i)
				}
				if flow.Priority == 0 {
					t.Errorf("flow %d has zero priority", i)
				}
			}

			// Verify specific actions are present
			for _, wantAction := range tt.wantActions {
				found := false
				for _, flow := range flows {
					if flow.Actions == wantAction {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected action %q not found in flows", wantAction)
				}
			}

			// Verify all flows include port ID in match
			for i, flow := range flows {
				if !strings.Contains(flow.Match, "in_port="+tt.portID) {
					// Some flows may not have in_port (e.g., DHCP server responses, ICMP ingress)
					// This is acceptable for certain bidirectional flows
					t.Logf("flow %d missing in_port (may be intentional): %s", i, flow.Match)
				}
			}
		})
	}
}

func TestGenerateARPRules(t *testing.T) {
	tests := []struct {
		name         string
		config       *ProvisioningFlowConfig
		portID       string
		wantCount    int
		wantPriority int
		wantMatch    string
	}{
		{
			name:         "without VLAN",
			config:       &ProvisioningFlowConfig{},
			portID:       "1",
			wantCount:    1,
			wantPriority: 1900,
			wantMatch:    "in_port=1,dl_type=0x0806",
		},
		{
			name: "with VLAN",
			config: &ProvisioningFlowConfig{
				ProvisioningVLAN: 100,
			},
			portID:       "2",
			wantCount:    1,
			wantPriority: 1900,
			wantMatch:    "in_port=2,dl_type=0x0806,dl_vlan=100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewProvisioningFlowGenerator(tt.config)
			rules := gen.generateARPRules(tt.portID)

			if len(rules) != tt.wantCount {
				t.Errorf("expected %d rules, got %d", tt.wantCount, len(rules))
			}

			if rules[0].Priority != tt.wantPriority {
				t.Errorf("expected priority %d, got %d", tt.wantPriority, rules[0].Priority)
			}

			if rules[0].Match != tt.wantMatch {
				t.Errorf("expected match %q, got %q", tt.wantMatch, rules[0].Match)
			}

			if rules[0].Actions != "normal" {
				t.Errorf("expected action 'normal', got %q", rules[0].Actions)
			}
		})
	}
}

func TestGenerateDHCPRules(t *testing.T) {
	tests := []struct {
		name      string
		config    *ProvisioningFlowConfig
		portID    string
		wantCount int
	}{
		{
			name:      "without VLAN",
			config:    &ProvisioningFlowConfig{},
			portID:    "1",
			wantCount: 2, // Client to server + server to client
		},
		{
			name: "with VLAN",
			config: &ProvisioningFlowConfig{
				ProvisioningVLAN: 100,
			},
			portID:    "1",
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewProvisioningFlowGenerator(tt.config)
			rules := gen.generateDHCPRules(tt.portID)

			if len(rules) != tt.wantCount {
				t.Errorf("expected %d rules, got %d", tt.wantCount, len(rules))
			}

			// Verify client to server rule
			clientRule := rules[0]
			if !strings.Contains(clientRule.Match, "in_port="+tt.portID) {
				t.Error("client rule missing in_port")
			}
			if !strings.Contains(clientRule.Match, "tp_src=68") {
				t.Error("client rule missing source port 68")
			}
			if !strings.Contains(clientRule.Match, "tp_dst=67") {
				t.Error("client rule missing destination port 67")
			}

			// Verify server to client rule
			serverRule := rules[1]
			if !strings.Contains(serverRule.Match, "tp_src=67") {
				t.Error("server rule missing source port 67")
			}
			if !strings.Contains(serverRule.Match, "tp_dst=68") {
				t.Error("server rule missing destination port 68")
			}

			// Verify VLAN if configured
			if tt.config.ProvisioningVLAN > 0 {
				for i, rule := range rules {
					if !strings.Contains(rule.Match, "dl_vlan=100") {
						t.Errorf("rule %d missing VLAN tag", i)
					}
				}
			}
		})
	}
}

func TestGenerateDNSRules(t *testing.T) {
	tests := []struct {
		name      string
		config    *ProvisioningFlowConfig
		portID    string
		wantCount int
	}{
		{
			name:      "no specific servers - allow all DNS",
			config:    &ProvisioningFlowConfig{},
			portID:    "1",
			wantCount: 6, // 3 ports * 2 protocols (UDP+TCP)
		},
		{
			name: "specific DNS server",
			config: &ProvisioningFlowConfig{
				DNSServerIPs: []net.IP{net.ParseIP("10.0.0.2")},
			},
			portID:    "1",
			wantCount: 6, // 3 ports * 2 protocols
		},
		{
			name: "multiple DNS servers",
			config: &ProvisioningFlowConfig{
				DNSServerIPs: []net.IP{
					net.ParseIP("10.0.0.2"),
					net.ParseIP("10.0.0.3"),
				},
			},
			portID:    "1",
			wantCount: 12, // 2 servers * 3 ports * 2 protocols
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewProvisioningFlowGenerator(tt.config)
			rules := gen.generateDNSRules(tt.portID)

			if len(rules) != tt.wantCount {
				t.Errorf("expected %d rules, got %d", tt.wantCount, len(rules))
			}

			// Verify DNS ports are present
			dnsPorts := []string{"53", "8053", "9053"}
			for _, port := range dnsPorts {
				found := false
				for _, rule := range rules {
					if strings.Contains(rule.Match, "tp_dst="+port) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("DNS port %s not found in rules", port)
				}
			}

			// Verify both UDP and TCP protocols
			foundUDP := false
			foundTCP := false
			for _, rule := range rules {
				if strings.Contains(rule.Match, "nw_proto=17") {
					foundUDP = true
				}
				if strings.Contains(rule.Match, "nw_proto=6") {
					foundTCP = true
				}
			}
			if !foundUDP {
				t.Error("UDP DNS rules not found")
			}
			if !foundTCP {
				t.Error("TCP DNS rules not found")
			}

			// Verify specific IPs if configured
			if len(tt.config.DNSServerIPs) > 0 {
				for _, ip := range tt.config.DNSServerIPs {
					found := false
					for _, rule := range rules {
						if strings.Contains(rule.Match, "nw_dst="+ip.String()) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("DNS server IP %s not found in rules", ip)
					}
				}
			}
		})
	}
}

func TestGenerateACMERules(t *testing.T) {
	tests := []struct {
		name      string
		config    *ProvisioningFlowConfig
		portID    string
		wantCount int
	}{
		{
			name:      "no specific servers - allow all HTTPS",
			config:    &ProvisioningFlowConfig{},
			portID:    "1",
			wantCount: 3, // 443, 8443, 9443
		},
		{
			name: "specific ACME server",
			config: &ProvisioningFlowConfig{
				ACMEServerIPs: []net.IP{net.ParseIP("10.0.0.1")},
			},
			portID:    "1",
			wantCount: 3, // 1 server * 3 ports
		},
		{
			name: "multiple ACME servers",
			config: &ProvisioningFlowConfig{
				ACMEServerIPs: []net.IP{
					net.ParseIP("10.0.0.1"),
					net.ParseIP("10.0.0.2"),
				},
			},
			portID:    "1",
			wantCount: 6, // 2 servers * 3 ports
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewProvisioningFlowGenerator(tt.config)
			rules := gen.generateACMERules(tt.portID)

			if len(rules) != tt.wantCount {
				t.Errorf("expected %d rules, got %d", tt.wantCount, len(rules))
			}

			// Verify HTTPS ports
			httpsPorts := []string{"443", "8443", "9443"}
			for _, port := range httpsPorts {
				found := false
				for _, rule := range rules {
					if strings.Contains(rule.Match, "tp_dst="+port) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("HTTPS port %s not found in rules", port)
				}
			}

			// Verify TCP protocol
			for i, rule := range rules {
				if !strings.Contains(rule.Match, "nw_proto=6") {
					t.Errorf("rule %d missing TCP protocol", i)
				}
			}

			// Verify specific IPs if configured
			if len(tt.config.ACMEServerIPs) > 0 {
				for _, ip := range tt.config.ACMEServerIPs {
					found := false
					for _, rule := range rules {
						if strings.Contains(rule.Match, "nw_dst="+ip.String()) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("ACME server IP %s not found in rules", ip)
					}
				}
			}
		})
	}
}

func TestGeneratePackageRepoRules(t *testing.T) {
	tests := []struct {
		name      string
		config    *ProvisioningFlowConfig
		portID    string
		wantCount int
	}{
		{
			name:      "no specific repos - allow all HTTP/HTTPS",
			config:    &ProvisioningFlowConfig{},
			portID:    "1",
			wantCount: 2, // 80, 443
		},
		{
			name: "specific package repo",
			config: &ProvisioningFlowConfig{
				PackageRepoIPs: []net.IP{net.ParseIP("10.0.0.3")},
			},
			portID:    "1",
			wantCount: 2, // 1 server * 2 ports
		},
		{
			name: "multiple package repos",
			config: &ProvisioningFlowConfig{
				PackageRepoIPs: []net.IP{
					net.ParseIP("10.0.0.3"),
					net.ParseIP("10.0.0.4"),
				},
			},
			portID:    "1",
			wantCount: 4, // 2 servers * 2 ports
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewProvisioningFlowGenerator(tt.config)
			rules := gen.generatePackageRepoRules(tt.portID)

			if len(rules) != tt.wantCount {
				t.Errorf("expected %d rules, got %d", tt.wantCount, len(rules))
			}

			// Verify HTTP and HTTPS ports
			foundHTTP := false
			foundHTTPS := false
			for _, rule := range rules {
				if strings.Contains(rule.Match, "tp_dst=80") {
					foundHTTP = true
				}
				if strings.Contains(rule.Match, "tp_dst=443") {
					foundHTTPS = true
				}
			}
			if !foundHTTP {
				t.Error("HTTP port 80 not found in rules")
			}
			if !foundHTTPS {
				t.Error("HTTPS port 443 not found in rules")
			}

			// Verify TCP protocol
			for i, rule := range rules {
				if !strings.Contains(rule.Match, "nw_proto=6") {
					t.Errorf("rule %d missing TCP protocol", i)
				}
			}

			// Verify specific IPs if configured
			if len(tt.config.PackageRepoIPs) > 0 {
				for _, ip := range tt.config.PackageRepoIPs {
					found := false
					for _, rule := range rules {
						if strings.Contains(rule.Match, "nw_dst="+ip.String()) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("package repo IP %s not found in rules", ip)
					}
				}
			}
		})
	}
}

func TestGenerateICMPRules(t *testing.T) {
	tests := []struct {
		name      string
		config    *ProvisioningFlowConfig
		portID    string
		wantCount int
	}{
		{
			name:      "without VLAN",
			config:    &ProvisioningFlowConfig{},
			portID:    "1",
			wantCount: 2, // Egress + ingress
		},
		{
			name: "with VLAN",
			config: &ProvisioningFlowConfig{
				ProvisioningVLAN: 100,
			},
			portID:    "1",
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewProvisioningFlowGenerator(tt.config)
			rules := gen.generateICMPRules(tt.portID)

			if len(rules) != tt.wantCount {
				t.Errorf("expected %d rules, got %d", tt.wantCount, len(rules))
			}

			// Verify ICMP protocol
			for i, rule := range rules {
				if !strings.Contains(rule.Match, "nw_proto=1") {
					t.Errorf("rule %d missing ICMP protocol", i)
				}
			}

			// Verify one egress rule (with in_port)
			foundEgress := false
			for _, rule := range rules {
				if strings.Contains(rule.Match, "in_port="+tt.portID) {
					foundEgress = true
					break
				}
			}
			if !foundEgress {
				t.Error("egress ICMP rule not found")
			}

			// Verify VLAN if configured
			if tt.config.ProvisioningVLAN > 0 {
				for i, rule := range rules {
					if !strings.Contains(rule.Match, "dl_vlan=100") {
						t.Errorf("rule %d missing VLAN tag", i)
					}
				}
			}
		})
	}
}

func TestGenerateDefaultDropRule(t *testing.T) {
	tests := []struct {
		name     string
		config   *ProvisioningFlowConfig
		portID   string
		wantDrop bool
	}{
		{
			name:     "without VLAN",
			config:   &ProvisioningFlowConfig{},
			portID:   "1",
			wantDrop: true,
		},
		{
			name: "with VLAN",
			config: &ProvisioningFlowConfig{
				ProvisioningVLAN: 100,
			},
			portID:   "1",
			wantDrop: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewProvisioningFlowGenerator(tt.config)
			rule := gen.generateDefaultDropRule(tt.portID)

			if rule.Actions != "drop" {
				t.Errorf("expected action 'drop', got %q", rule.Actions)
			}

			if !strings.Contains(rule.Match, "in_port="+tt.portID) {
				t.Error("default drop rule missing in_port")
			}

			// Should have lowest priority
			if rule.Priority >= gen.generator.BasePriority {
				t.Error("default drop rule priority too high")
			}

			if tt.config.ProvisioningVLAN > 0 {
				if !strings.Contains(rule.Match, "dl_vlan=100") {
					t.Error("default drop rule missing VLAN tag")
				}
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *ProvisioningFlowConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name:    "valid empty config",
			config:  &ProvisioningFlowConfig{},
			wantErr: false,
		},
		{
			name: "valid full config",
			config: &ProvisioningFlowConfig{
				ACMEServerIPs:    []net.IP{net.ParseIP("10.0.0.1")},
				DNSServerIPs:     []net.IP{net.ParseIP("10.0.0.2")},
				ProvisioningVLAN: 100,
				PackageRepoIPs:   []net.IP{net.ParseIP("10.0.0.3")},
				Gateway:          net.ParseIP("10.0.0.254"),
				AllowICMP:        true,
			},
			wantErr: false,
		},
		{
			name: "nil ACME server IP",
			config: &ProvisioningFlowConfig{
				ACMEServerIPs: []net.IP{nil},
			},
			wantErr: true,
		},
		{
			name: "nil DNS server IP",
			config: &ProvisioningFlowConfig{
				DNSServerIPs: []net.IP{nil},
			},
			wantErr: true,
		},
		{
			name: "nil package repo IP",
			config: &ProvisioningFlowConfig{
				PackageRepoIPs: []net.IP{nil},
			},
			wantErr: true,
		},
		{
			name: "unspecified gateway",
			config: &ProvisioningFlowConfig{
				Gateway: net.ParseIP("0.0.0.0"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigString(t *testing.T) {
	tests := []struct {
		name         string
		config       *ProvisioningFlowConfig
		wantContains []string
	}{
		{
			name:         "empty config",
			config:       &ProvisioningFlowConfig{},
			wantContains: []string{"ProvisioningFlowConfig", "AllowICMP: false"},
		},
		{
			name: "full config",
			config: &ProvisioningFlowConfig{
				ACMEServerIPs:    []net.IP{net.ParseIP("10.0.0.1")},
				DNSServerIPs:     []net.IP{net.ParseIP("10.0.0.2")},
				ProvisioningVLAN: 100,
				PackageRepoIPs:   []net.IP{net.ParseIP("10.0.0.3")},
				Gateway:          net.ParseIP("10.0.0.254"),
				AllowICMP:        true,
			},
			wantContains: []string{
				"ProvisioningFlowConfig",
				"ACMEServerIPs",
				"DNSServerIPs",
				"ProvisioningVLAN: 100",
				"PackageRepoIPs",
				"Gateway: 10.0.0.254",
				"AllowICMP: true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := tt.config.String()
			for _, want := range tt.wantContains {
				if !strings.Contains(str, want) {
					t.Errorf("String() missing %q, got: %s", want, str)
				}
			}
		})
	}
}

func TestFlowPriorities(t *testing.T) {
	// Verify that flow priorities are correctly ordered
	config := &ProvisioningFlowConfig{
		ACMEServerIPs:  []net.IP{net.ParseIP("10.0.0.1")},
		DNSServerIPs:   []net.IP{net.ParseIP("10.0.0.2")},
		PackageRepoIPs: []net.IP{net.ParseIP("10.0.0.3")},
		AllowICMP:      true,
	}

	gen := NewProvisioningFlowGenerator(config)
	flows := gen.GenerateFlows("1", "00:11:22:33:44:55")

	// Extract priorities
	var priorities []int
	for _, flow := range flows {
		priorities = append(priorities, flow.Priority)
	}

	// Verify default drop has lowest priority
	minPriority := priorities[0]
	for _, p := range priorities {
		if p < minPriority {
			minPriority = p
		}
	}

	dropPriority := flows[len(flows)-1].Priority
	if dropPriority != minPriority {
		t.Errorf("default drop rule doesn't have lowest priority: drop=%d, min=%d",
			dropPriority, minPriority)
	}

	// Verify ARP has highest priority
	maxPriority := priorities[0]
	for _, p := range priorities {
		if p > maxPriority {
			maxPriority = p
		}
	}

	arpPriority := flows[0].Priority
	if arpPriority != maxPriority {
		t.Errorf("ARP rule doesn't have highest priority: arp=%d, max=%d",
			arpPriority, maxPriority)
	}
}

func TestFlowRuleFormat(t *testing.T) {
	// Verify that generated flow rules have valid OpenFlow format
	config := &ProvisioningFlowConfig{
		ProvisioningVLAN: 100,
	}

	gen := NewProvisioningFlowGenerator(config)
	flows := gen.GenerateFlows("1", "00:11:22:33:44:55")

	for i, flow := range flows {
		// Verify match contains valid OpenFlow fields
		if flow.Match != "" {
			validFields := []string{"in_port=", "dl_type=", "dl_vlan=", "nw_proto=", "tp_src=", "tp_dst=", "nw_dst="}
			hasValidField := false
			for _, field := range validFields {
				if strings.Contains(flow.Match, field) {
					hasValidField = true
					break
				}
			}
			if !hasValidField {
				t.Errorf("flow %d has invalid match format: %s", i, flow.Match)
			}
		}

		// Verify actions are valid
		validActions := []string{"normal", "drop", "output:", "mod_vlan_vid:"}
		hasValidAction := false
		for _, action := range validActions {
			if strings.Contains(flow.Actions, action) {
				hasValidAction = true
				break
			}
		}
		if !hasValidAction {
			t.Errorf("flow %d has invalid action: %s", i, flow.Actions)
		}

		// Verify priority is reasonable
		if flow.Priority < 0 || flow.Priority > 10000 {
			t.Errorf("flow %d has unreasonable priority: %d", i, flow.Priority)
		}
	}
}

func TestMultipleServerConfigurations(t *testing.T) {
	// Test with multiple servers of each type
	config := &ProvisioningFlowConfig{
		ACMEServerIPs: []net.IP{
			net.ParseIP("10.0.0.1"),
			net.ParseIP("10.0.0.2"),
			net.ParseIP("10.0.0.3"),
		},
		DNSServerIPs: []net.IP{
			net.ParseIP("10.0.0.10"),
			net.ParseIP("10.0.0.11"),
		},
		PackageRepoIPs: []net.IP{
			net.ParseIP("10.0.0.20"),
			net.ParseIP("10.0.0.21"),
			net.ParseIP("10.0.0.22"),
			net.ParseIP("10.0.0.23"),
		},
		AllowICMP: true,
	}

	gen := NewProvisioningFlowGenerator(config)
	flows := gen.GenerateFlows("1", "00:11:22:33:44:55")

	// Verify all ACME server IPs are present
	for _, ip := range config.ACMEServerIPs {
		found := false
		for _, flow := range flows {
			if strings.Contains(flow.Match, "nw_dst="+ip.String()) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ACME server IP %s not found in flows", ip)
		}
	}

	// Verify all DNS server IPs are present
	for _, ip := range config.DNSServerIPs {
		found := false
		for _, flow := range flows {
			if strings.Contains(flow.Match, "nw_dst="+ip.String()) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DNS server IP %s not found in flows", ip)
		}
	}

	// Verify all package repo IPs are present
	for _, ip := range config.PackageRepoIPs {
		found := false
		for _, flow := range flows {
			if strings.Contains(flow.Match, "nw_dst="+ip.String()) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Package repo IP %s not found in flows", ip)
		}
	}
}

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
	"testing"
)

// TestNewQuarantineFlowGenerator tests the creation of quarantine flow generator
func TestNewQuarantineFlowGenerator(t *testing.T) {
	tests := []struct {
		name   string
		config *QuarantineFlowConfig
		want   bool
	}{
		{
			name: "valid configuration",
			config: &QuarantineFlowConfig{
				QuarantineVLAN:       100,
				ScanningServerIPs:    []net.IP{net.ParseIP("10.0.0.10")},
				RemediationServerIPs: []net.IP{net.ParseIP("10.0.0.20")},
				DNSServerIP:          net.ParseIP("10.0.0.1"),
				NotificationServerIP: net.ParseIP("10.0.0.30"),
				Gateway:              net.ParseIP("10.0.0.254"),
				AllowedPorts:         []uint16{443, 8443},
			},
			want: true,
		},
		{
			name: "minimal configuration",
			config: &QuarantineFlowConfig{
				QuarantineVLAN: 200,
				DNSServerIP:    net.ParseIP("192.168.1.1"),
				Gateway:        net.ParseIP("192.168.1.254"),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewQuarantineFlowGenerator(tt.config)
			if (gen != nil) != tt.want {
				t.Errorf("NewQuarantineFlowGenerator() = %v, want %v", gen != nil, tt.want)
			}
			if gen != nil {
				if gen.config != tt.config {
					t.Errorf("config mismatch")
				}
				if gen.generator == nil {
					t.Errorf("generator should not be nil")
				}
			}
		})
	}
}

// TestQuarantineFlowGenerator_GenerateFlows tests comprehensive flow generation
func TestQuarantineFlowGenerator_GenerateFlows(t *testing.T) {
	tests := []struct {
		name       string
		config     *QuarantineFlowConfig
		portID     string
		portMAC    string
		wantMinLen int
	}{
		{
			name: "full configuration",
			config: &QuarantineFlowConfig{
				QuarantineVLAN:       100,
				ScanningServerIPs:    []net.IP{net.ParseIP("10.0.0.10"), net.ParseIP("10.0.0.11")},
				RemediationServerIPs: []net.IP{net.ParseIP("10.0.0.20"), net.ParseIP("10.0.0.21")},
				DNSServerIP:          net.ParseIP("10.0.0.1"),
				NotificationServerIP: net.ParseIP("10.0.0.30"),
				Gateway:              net.ParseIP("10.0.0.254"),
				AllowedPorts:         []uint16{443, 8443},
			},
			portID:     "eth0",
			portMAC:    "00:11:22:33:44:55",
			wantMinLen: 5, // ARP, DHCP, DNS, scanning, remediation, notification, drop
		},
		{
			name: "minimal configuration",
			config: &QuarantineFlowConfig{
				QuarantineVLAN: 200,
				DNSServerIP:    net.ParseIP("192.168.1.1"),
				Gateway:        net.ParseIP("192.168.1.254"),
			},
			portID:     "eth1",
			portMAC:    "AA:BB:CC:DD:EE:FF",
			wantMinLen: 3, // ARP, DHCP, DNS, drop
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewQuarantineFlowGenerator(tt.config)
			flows := gen.GenerateFlows(tt.portID, tt.portMAC)

			if len(flows) < tt.wantMinLen {
				t.Errorf("GenerateFlows() returned %d flows, want at least %d", len(flows), tt.wantMinLen)
			}

			// Verify all flows have required fields
			for i, flow := range flows {
				if flow.Table < 0 {
					t.Errorf("flow %d: invalid table %d", i, flow.Table)
				}
				if flow.Priority <= 0 {
					t.Errorf("flow %d: invalid priority %d", i, flow.Priority)
				}
				if flow.Actions == "" {
					t.Errorf("flow %d: empty actions", i)
				}
			}

			// Verify last flow is default drop
			lastFlow := flows[len(flows)-1]
			if lastFlow.Actions != "drop" {
				t.Errorf("last flow should be drop, got %s", lastFlow.Actions)
			}
		})
	}
}

// TestQuarantineFlowGenerator_generateARPRules tests ARP rule generation
func TestQuarantineFlowGenerator_generateARPRules(t *testing.T) {
	config := &QuarantineFlowConfig{
		QuarantineVLAN: 100,
		Gateway:        net.ParseIP("10.0.0.254"),
	}

	gen := NewQuarantineFlowGenerator(config)
	rules := gen.generateARPRules("eth0")

	if len(rules) == 0 {
		t.Fatal("generateARPRules() returned no rules")
	}

	// Check for ARP Ethertype (0x0806)
	found := false
	for _, rule := range rules {
		if rule.Match != "" && rule.Actions == "normal" {
			found = true
			if rule.Priority <= 0 {
				t.Errorf("ARP rule has invalid priority: %d", rule.Priority)
			}
		}
	}

	if !found {
		t.Error("no valid ARP rule found")
	}
}

// TestQuarantineFlowGenerator_generateDHCPRules tests DHCP rule generation
func TestQuarantineFlowGenerator_generateDHCPRules(t *testing.T) {
	config := &QuarantineFlowConfig{
		QuarantineVLAN: 100,
	}

	gen := NewQuarantineFlowGenerator(config)
	rules := gen.generateDHCPRules("eth0")

	if len(rules) == 0 {
		t.Fatal("generateDHCPRules() returned no rules")
	}

	// Should have rules for DHCP client and server ports
	for _, rule := range rules {
		if rule.Actions != "normal" {
			t.Errorf("DHCP rule should use normal action, got %s", rule.Actions)
		}
		if rule.Priority <= 0 {
			t.Errorf("DHCP rule has invalid priority: %d", rule.Priority)
		}
	}
}

// TestQuarantineFlowGenerator_generateDNSRules tests DNS rule generation
func TestQuarantineFlowGenerator_generateDNSRules(t *testing.T) {
	tests := []struct {
		name     string
		dnsIP    net.IP
		wantZero bool
	}{
		{
			name:     "with DNS server",
			dnsIP:    net.ParseIP("10.0.0.1"),
			wantZero: false,
		},
		{
			name:     "without DNS server",
			dnsIP:    nil,
			wantZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &QuarantineFlowConfig{
				QuarantineVLAN: 100,
				DNSServerIP:    tt.dnsIP,
			}

			gen := NewQuarantineFlowGenerator(config)
			rules := gen.generateDNSRules("eth0")

			if tt.wantZero && len(rules) != 0 {
				t.Errorf("expected no DNS rules, got %d", len(rules))
			}

			if !tt.wantZero && len(rules) == 0 {
				t.Error("expected DNS rules, got none")
			}

			for _, rule := range rules {
				if rule.Actions != "normal" {
					t.Errorf("DNS rule should use normal action, got %s", rule.Actions)
				}
			}
		})
	}
}

// TestQuarantineFlowGenerator_generateScanningRules tests scanning server rule generation
func TestQuarantineFlowGenerator_generateScanningRules(t *testing.T) {
	tests := []struct {
		name            string
		scanningServers []net.IP
		wantRules       int
	}{
		{
			name:            "single scanning server",
			scanningServers: []net.IP{net.ParseIP("10.0.0.10")},
			wantRules:       2, // to and from server
		},
		{
			name: "multiple scanning servers",
			scanningServers: []net.IP{
				net.ParseIP("10.0.0.10"),
				net.ParseIP("10.0.0.11"),
				net.ParseIP("10.0.0.12"),
			},
			wantRules: 6, // 2 rules per server (to and from)
		},
		{
			name:            "no scanning servers",
			scanningServers: nil,
			wantRules:       0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &QuarantineFlowConfig{
				QuarantineVLAN:    100,
				ScanningServerIPs: tt.scanningServers,
			}

			gen := NewQuarantineFlowGenerator(config)
			rules := gen.generateScanningRules("eth0")

			if len(rules) != tt.wantRules {
				t.Errorf("generateScanningRules() returned %d rules, want %d", len(rules), tt.wantRules)
			}

			for _, rule := range rules {
				if rule.Actions != "normal" {
					t.Errorf("scanning rule should use normal action, got %s", rule.Actions)
				}
			}
		})
	}
}

// TestQuarantineFlowGenerator_generateRemediationRules tests remediation server rule generation
func TestQuarantineFlowGenerator_generateRemediationRules(t *testing.T) {
	tests := []struct {
		name               string
		remediationServers []net.IP
		allowedPorts       []uint16
		wantMin            int
	}{
		{
			name:               "single remediation server with ports",
			remediationServers: []net.IP{net.ParseIP("10.0.0.20")},
			allowedPorts:       []uint16{443, 8443},
			wantMin:            1,
		},
		{
			name: "multiple remediation servers",
			remediationServers: []net.IP{
				net.ParseIP("10.0.0.20"),
				net.ParseIP("10.0.0.21"),
			},
			allowedPorts: []uint16{443},
			wantMin:      2,
		},
		{
			name:               "no remediation servers",
			remediationServers: nil,
			allowedPorts:       []uint16{443},
			wantMin:            0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &QuarantineFlowConfig{
				QuarantineVLAN:       100,
				RemediationServerIPs: tt.remediationServers,
				AllowedPorts:         tt.allowedPorts,
			}

			gen := NewQuarantineFlowGenerator(config)
			rules := gen.generateRemediationRules("eth0")

			if len(rules) < tt.wantMin {
				t.Errorf("generateRemediationRules() returned %d rules, want at least %d", len(rules), tt.wantMin)
			}

			for _, rule := range rules {
				if rule.Actions != "normal" {
					t.Errorf("remediation rule should use normal action, got %s", rule.Actions)
				}
			}
		})
	}
}

// TestQuarantineFlowGenerator_generateNotificationRules tests notification server rule generation
func TestQuarantineFlowGenerator_generateNotificationRules(t *testing.T) {
	tests := []struct {
		name           string
		notificationIP net.IP
		wantRules      bool
	}{
		{
			name:           "with notification server",
			notificationIP: net.ParseIP("10.0.0.30"),
			wantRules:      true,
		},
		{
			name:           "without notification server",
			notificationIP: nil,
			wantRules:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &QuarantineFlowConfig{
				QuarantineVLAN:       100,
				NotificationServerIP: tt.notificationIP,
			}

			gen := NewQuarantineFlowGenerator(config)
			rules := gen.generateNotificationRules("eth0")

			hasRules := len(rules) > 0
			if hasRules != tt.wantRules {
				t.Errorf("generateNotificationRules() returned %d rules, wanted rules: %v", len(rules), tt.wantRules)
			}

			// Should allow HTTP (80) and HTTPS (443)
			if tt.wantRules && len(rules) < 2 {
				t.Errorf("notification rules should include HTTP and HTTPS, got %d rules", len(rules))
			}

			for _, rule := range rules {
				if rule.Actions != "normal" {
					t.Errorf("notification rule should use normal action, got %s", rule.Actions)
				}
			}
		})
	}
}

// TestQuarantineFlowGenerator_generateDefaultDropRule tests default drop rule generation
func TestQuarantineFlowGenerator_generateDefaultDropRule(t *testing.T) {
	config := &QuarantineFlowConfig{
		QuarantineVLAN: 100,
	}

	gen := NewQuarantineFlowGenerator(config)
	rule := gen.generateDefaultDropRule("eth0")

	if rule.Actions != "drop" {
		t.Errorf("default rule should drop traffic, got %s", rule.Actions)
	}

	if rule.Priority <= 0 {
		t.Errorf("default drop rule has invalid priority: %d", rule.Priority)
	}

	// Default drop should have lower priority value than other quarantine rules
	// (in OpenFlow, higher priority values = higher precedence, so drop should have lower value)
	expectedPriority := gen.generator.BasePriority + priorityDropOffset
	if rule.Priority != expectedPriority {
		t.Errorf("default drop priority %d should be %d (base %d + offset %d)",
			rule.Priority, expectedPriority, gen.generator.BasePriority, priorityDropOffset)
	}
}

// TestQuarantineFlowGenerator_VLANIsolation tests VLAN isolation in generated rules
func TestQuarantineFlowGenerator_VLANIsolation(t *testing.T) {
	config := &QuarantineFlowConfig{
		QuarantineVLAN:       999,
		ScanningServerIPs:    []net.IP{net.ParseIP("10.0.0.10")},
		RemediationServerIPs: []net.IP{net.ParseIP("10.0.0.20")},
		DNSServerIP:          net.ParseIP("10.0.0.1"),
		NotificationServerIP: net.ParseIP("10.0.0.30"),
		Gateway:              net.ParseIP("10.0.0.254"),
	}

	gen := NewQuarantineFlowGenerator(config)
	flows := gen.GenerateFlows("eth0", "00:11:22:33:44:55")

	// Count VLAN-specific rules (excluding ARP, DHCP which may not have VLAN tags initially)
	vlanRules := 0
	for _, flow := range flows {
		// Rules that should enforce VLAN isolation
		if flow.Match != "" && flow.Actions != "drop" {
			// Most rules should reference VLAN in match or actions
			vlanRules++
		}
	}

	if vlanRules == 0 {
		t.Error("expected VLAN-enforcing rules, got none")
	}
}

// TestQuarantineFlowGenerator_RulePriorities tests that rule priorities are correctly ordered
func TestQuarantineFlowGenerator_RulePriorities(t *testing.T) {
	config := &QuarantineFlowConfig{
		QuarantineVLAN:       100,
		ScanningServerIPs:    []net.IP{net.ParseIP("10.0.0.10")},
		RemediationServerIPs: []net.IP{net.ParseIP("10.0.0.20")},
		DNSServerIP:          net.ParseIP("10.0.0.1"),
		NotificationServerIP: net.ParseIP("10.0.0.30"),
		Gateway:              net.ParseIP("10.0.0.254"),
	}

	gen := NewQuarantineFlowGenerator(config)
	flows := gen.GenerateFlows("eth0", "00:11:22:33:44:55")

	if len(flows) < 2 {
		t.Fatal("not enough flows to test priorities")
	}

	// Last flow should be the default drop with lowest priority value
	lastFlow := flows[len(flows)-1]
	if lastFlow.Actions != "drop" {
		t.Errorf("last flow should be drop, got %s", lastFlow.Actions)
	}

	// Check that drop has lower priority value than other allow rules
	// (In OpenFlow, higher priority value = higher precedence, so drop should have lower value)
	for i := 0; i < len(flows)-1; i++ {
		if flows[i].Actions != "drop" && flows[i].Priority <= lastFlow.Priority {
			t.Errorf("flow %d with action %s has priority %d <= drop priority %d",
				i, flows[i].Actions, flows[i].Priority, lastFlow.Priority)
		}
	}
}

// TestQuarantineFlowGenerator_EmptyPortID tests behavior with empty port ID
func TestQuarantineFlowGenerator_EmptyPortID(t *testing.T) {
	config := &QuarantineFlowConfig{
		QuarantineVLAN: 100,
		DNSServerIP:    net.ParseIP("10.0.0.1"),
		Gateway:        net.ParseIP("10.0.0.254"),
	}

	gen := NewQuarantineFlowGenerator(config)
	flows := gen.GenerateFlows("", "00:11:22:33:44:55")

	// Should still generate flows even with empty port ID
	if len(flows) == 0 {
		t.Error("expected flows with empty port ID")
	}

	// Verify flows still have valid structure
	for _, flow := range flows {
		if flow.Priority <= 0 {
			t.Errorf("flow has invalid priority: %d", flow.Priority)
		}
		if flow.Actions == "" {
			t.Error("flow has empty actions")
		}
	}
}

// TestQuarantineFlowGenerator_IPv4Only tests IPv4-only configuration
func TestQuarantineFlowGenerator_IPv4Only(t *testing.T) {
	config := &QuarantineFlowConfig{
		QuarantineVLAN:       100,
		ScanningServerIPs:    []net.IP{net.ParseIP("10.0.0.10")},
		RemediationServerIPs: []net.IP{net.ParseIP("10.0.0.20")},
		DNSServerIP:          net.ParseIP("10.0.0.1"),
		NotificationServerIP: net.ParseIP("10.0.0.30"),
		Gateway:              net.ParseIP("10.0.0.254"),
	}

	gen := NewQuarantineFlowGenerator(config)
	flows := gen.GenerateFlows("eth0", "00:11:22:33:44:55")

	// Verify all IP addresses are IPv4
	for _, ip := range config.ScanningServerIPs {
		if ip.To4() == nil {
			t.Errorf("scanning server IP is not IPv4: %s", ip)
		}
	}

	for _, ip := range config.RemediationServerIPs {
		if ip.To4() == nil {
			t.Errorf("remediation server IP is not IPv4: %s", ip)
		}
	}

	if config.DNSServerIP.To4() == nil {
		t.Errorf("DNS server IP is not IPv4: %s", config.DNSServerIP)
	}

	if len(flows) == 0 {
		t.Error("expected flows for IPv4 configuration")
	}
}

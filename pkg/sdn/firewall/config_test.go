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

func TestConfig_ValidateValid(t *testing.T) {
	cfg := testConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid config: unexpected error %v", err)
	}
}

func TestConfig_ValidateNil(t *testing.T) {
	var cfg *Config
	if err := cfg.Validate(); err != ErrInvalidConfig {
		t.Errorf("nil config: got %v, want ErrInvalidConfig", err)
	}
}

func TestConfig_ValidateDisabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled config should not error: got %v", err)
	}
}

func TestConfig_ValidateInvalidPolicy(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: "maybe",
	}
	if err := cfg.Validate(); err != ErrInvalidDefaultPolicy {
		t.Errorf("bad policy: got %v, want ErrInvalidDefaultPolicy", err)
	}
}

func TestConfig_ValidateZoneMissingName(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: "deny",
		Zones: []Zone{
			{Name: ""},
		},
	}
	if err := cfg.Validate(); err != ErrZoneMissingName {
		t.Errorf("zone no name: got %v, want ErrZoneMissingName", err)
	}
}

func TestConfig_ValidateDuplicateZone(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: "deny",
		Zones: []Zone{
			{Name: "wan"},
			{Name: "wan"},
		},
	}
	if err := cfg.Validate(); err != ErrDuplicateZone {
		t.Errorf("dup zone: got %v, want ErrDuplicateZone", err)
	}
}

func TestConfig_ValidateRuleMissingName(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: "deny",
		Rules: []Rule{
			{Name: ""},
		},
	}
	if err := cfg.Validate(); err != ErrRuleMissingName {
		t.Errorf("rule no name: got %v, want ErrRuleMissingName", err)
	}
}

func TestConfig_ValidateNATRuleMissingName(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: "deny",
		NAT: NATConfig{
			SNAT: []NATRule{{Name: ""}},
		},
	}
	if err := cfg.Validate(); err != ErrNATRuleMissingName {
		t.Errorf("SNAT no name: got %v, want ErrNATRuleMissingName", err)
	}
}

func TestConfig_ValidateDNATMissingTarget(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: "deny",
		NAT: NATConfig{
			DNAT: []NATRule{
				{
					Name:     "bad-dnat",
					Type:     NATTypeDNAT,
					DstPort:  80,
					TargetIP: netip.Addr{},
				},
			},
		},
	}
	if err := cfg.Validate(); err != ErrNATRuleInvalidTarget {
		t.Errorf("DNAT no target: got %v, want ErrNATRuleInvalidTarget", err)
	}
}

func TestConfig_ValidateDNATMissingPort(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: "deny",
		NAT: NATConfig{
			DNAT: []NATRule{
				{
					Name:       "bad-dnat-port",
					Type:       NATTypeDNAT,
					DstPort:    80,
					TargetIP:   netip.MustParseAddr("10.0.0.1"),
					TargetPort: 0,
				},
			},
		},
	}
	if err := cfg.Validate(); err != ErrNATRuleInvalidTarget {
		t.Errorf("DNAT no target port: got %v, want ErrNATRuleInvalidTarget", err)
	}
}

func TestDefaultTimeouts(t *testing.T) {
	d := DefaultTimeouts()
	if d.TCPEstablished == 0 || d.TCPClose == 0 || d.UDP == 0 || d.ICMP == 0 {
		t.Error("default timeouts should all be non-zero")
	}
}

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

import "time"

// Config is the top-level firewall configuration.
type Config struct {
	// Enabled controls whether the firewall engine is active.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// DefaultPolicy is the action for packets that match no rule.
	// Must be "allow" or "deny".
	DefaultPolicy string `yaml:"default-policy" json:"default_policy" mapstructure:"default-policy"`

	// Zones defines the network zones.
	Zones []Zone `yaml:"zones" json:"zones" mapstructure:"zones"`

	// Rules defines the firewall rules, evaluated in priority order.
	Rules []Rule `yaml:"rules" json:"rules" mapstructure:"rules"`

	// NAT configures network address translation.
	NAT NATConfig `yaml:"nat,omitempty" json:"nat,omitempty" mapstructure:"nat"`

	// Timeouts configures connection tracking timeouts.
	Timeouts ConnTrackTimeouts `yaml:"timeouts,omitempty" json:"timeouts,omitempty" mapstructure:"timeouts"`
}

// NATConfig groups SNAT and DNAT rules.
type NATConfig struct {
	// SNAT is the list of source NAT rules.
	SNAT []NATRule `yaml:"snat,omitempty" json:"snat,omitempty" mapstructure:"snat"`

	// DNAT is the list of destination NAT rules.
	DNAT []NATRule `yaml:"dnat,omitempty" json:"dnat,omitempty" mapstructure:"dnat"`
}

// DefaultTimeouts returns the default connection tracking timeouts.
func DefaultTimeouts() ConnTrackTimeouts {
	return ConnTrackTimeouts{
		TCPEstablished: 5 * time.Minute,
		TCPClose:       30 * time.Second,
		UDP:            30 * time.Second,
		ICMP:           30 * time.Second,
	}
}

// Validate checks the firewall configuration for correctness.
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}
	if !c.Enabled {
		return nil
	}
	if c.DefaultPolicy != "allow" && c.DefaultPolicy != "deny" {
		return ErrInvalidDefaultPolicy
	}
	zoneNames := make(map[string]struct{}, len(c.Zones))
	for i := range c.Zones {
		if c.Zones[i].Name == "" {
			return ErrZoneMissingName
		}
		if _, ok := zoneNames[c.Zones[i].Name]; ok {
			return ErrDuplicateZone
		}
		zoneNames[c.Zones[i].Name] = struct{}{}
	}
	for i := range c.Rules {
		if c.Rules[i].Name == "" {
			return ErrRuleMissingName
		}
	}
	for i := range c.NAT.SNAT {
		if c.NAT.SNAT[i].Name == "" {
			return ErrNATRuleMissingName
		}
	}
	for i := range c.NAT.DNAT {
		if c.NAT.DNAT[i].Name == "" {
			return ErrNATRuleMissingName
		}
		if !c.NAT.DNAT[i].TargetIP.IsValid() || c.NAT.DNAT[i].TargetPort == 0 {
			return ErrNATRuleInvalidTarget
		}
	}
	return nil
}

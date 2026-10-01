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

package netplan

import (
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// Environment holds the inputs every number of one environment is derived
// from. It is the sdn.environment configuration section.
//
// YAML form:
//
//	environment:
//	  id: 4
//	  base: 10.0.0.0/8
//	  ula: fd12:3456:789a::/48
//	  overrides:
//	    - {zone: fabric, subnet: 10.4.100.0/22}
type Environment struct {
	// ID is the environment number E (2-40): its VLAN block is E·100-E·100+99,
	// its IPv4 /16 is <base>.E.0.0/16 and its VNIs are E·100000+n.
	ID uint16 `yaml:"id" json:"id" mapstructure:"id"`

	// Base is the IPv4 /8 the environment's /16 is taken from. Empty means
	// DefaultBase (10.0.0.0/8).
	Base netip.Prefix `yaml:"base,omitempty" json:"base,omitempty" mapstructure:"base"`

	// ULA is the deployment's RFC 4193 /48 (random global ID). Every
	// environment of a deployment shares it; the VLAN digits keep their
	// subnets apart. Empty means the plan derives no IPv6 subnets.
	ULA netip.Prefix `yaml:"ula,omitempty" json:"ula,omitempty" mapstructure:"ula"`

	// Overrides replace derived numbers for individual zones. The reference
	// needs none; the dev fleet and other non-reference sites use them.
	Overrides []Override `yaml:"overrides,omitempty" json:"overrides,omitempty" mapstructure:"overrides"`
}

// Override replaces the derived numbering of one zone. A zero field keeps
// the derived value. The zone keeps its offset: an override changes where a
// zone lives, not which zone it is.
type Override struct {
	// Zone is the zone whose numbering is replaced.
	Zone zone.Zone `yaml:"zone" json:"zone" mapstructure:"zone"`

	// VLAN replaces the derived VLAN ID (1-4094).
	VLAN uint16 `yaml:"vlan,omitempty" json:"vlan,omitempty" mapstructure:"vlan"`

	// Subnet replaces the derived IPv4 subnet. Any prefix from /16 to /26
	// is accepted (a /26 is the smallest subnet that still holds the
	// reference host bands and a DHCP range from .50), so a wider fabric (for example a /22 in the unused
	// <base>.E.100.0-<base>.E.127.255 range) is an override.
	Subnet netip.Prefix `yaml:"subnet,omitempty" json:"subnet,omitempty" mapstructure:"subnet"`

	// Subnet6 replaces the derived IPv6 subnet; it must be a /64.
	Subnet6 netip.Prefix `yaml:"subnet6,omitempty" json:"subnet6,omitempty" mapstructure:"subnet6"`
}

// EffectiveBase returns Base, or DefaultBase when Base is empty.
func (e Environment) EffectiveBase() netip.Prefix {
	if !e.Base.IsValid() {
		return DefaultBase
	}
	return e.Base
}

// Validate checks the environment number, base and ULA, and the shape of
// each override. Whether an override names a declared zone, and whether the
// resulting numbers collide, is checked by New against the zone set.
func (e Environment) Validate() error {
	if e.ID < MinEnvironment || e.ID > MaxEnvironment {
		return ErrEnvironmentID{ID: e.ID}
	}
	if err := validateBase(e.EffectiveBase()); err != nil {
		return err
	}
	if e.ULA.IsValid() {
		if err := validateULA(e.ULA); err != nil {
			return err
		}
	}
	seen := make(map[zone.Zone]struct{}, len(e.Overrides))
	for _, o := range e.Overrides {
		if err := o.validate(); err != nil {
			return err
		}
		if _, dup := seen[o.Zone]; dup {
			return ErrOverride{Zone: o.Zone, Reason: "the zone is overridden twice"}
		}
		seen[o.Zone] = struct{}{}
	}
	return nil
}

// validate checks the shape of one override.
func (o Override) validate() error {
	if o.Zone == "" {
		return ErrOverride{Reason: "zone is required"}
	}
	if o.VLAN == 0 && !o.Subnet.IsValid() && !o.Subnet6.IsValid() {
		return ErrOverride{Zone: o.Zone, Reason: "it overrides nothing (set vlan, subnet or subnet6)"}
	}
	if o.VLAN > MaxVLAN {
		return ErrOverride{Zone: o.Zone, Reason: "vlan must be 1-4094"}
	}
	if o.Subnet.IsValid() {
		if !o.Subnet.Addr().Is4() || o.Subnet.Bits() < 16 || o.Subnet.Bits() > 26 || o.Subnet.Masked() != o.Subnet {
			return ErrOverride{Zone: o.Zone, Reason: "subnet must be a masked IPv4 prefix from /16 to /26"}
		}
	}
	if o.Subnet6.IsValid() {
		if !o.Subnet6.Addr().Is6() || o.Subnet6.Addr().Is4In6() || o.Subnet6.Bits() != 64 || o.Subnet6.Masked() != o.Subnet6 {
			return ErrOverride{Zone: o.Zone, Reason: "subnet6 must be a masked IPv6 /64"}
		}
	}
	return nil
}

// override returns the override for z, if any.
func (e Environment) override(z zone.Zone) (Override, bool) {
	for _, o := range e.Overrides {
		if o.Zone == z {
			return o, true
		}
	}
	return Override{}, false
}

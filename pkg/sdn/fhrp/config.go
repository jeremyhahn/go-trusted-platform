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

package fhrp

import (
	"net/netip"
	"strings"
)

// Config is the `fhrp:` section of a gateway configuration.
type Config struct {
	// Enabled turns the speaker on.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	// Groups are the virtual routers this node participates in.
	Groups []GroupConfig `yaml:"groups" json:"groups" mapstructure:"groups"`
}

// GroupConfig is one VRRPv3 virtual router on one interface.
type GroupConfig struct {
	// VRID is the virtual router identifier (1–255); it selects the
	// virtual MAC and identifies the group on the segment.
	VRID uint8 `yaml:"vrid" json:"vrid" mapstructure:"vrid"`
	// Interface is the Linux interface (or OVS internal port) the group
	// advertises on and the virtual addresses are programmed on.
	Interface string `yaml:"interface" json:"interface" mapstructure:"interface"`
	// Priority is 1–254 for a backup, 255 for the address owner; zero
	// takes the RFC default of 100.
	Priority uint8 `yaml:"priority" json:"priority" mapstructure:"priority"`
	// AdvertIntervalCentiseconds is Master_Adver_Interval (1–4095, RFC
	// default 100 = 1 s).
	AdvertIntervalCentiseconds uint16 `yaml:"advert-interval-cs" json:"advert_interval_cs" mapstructure:"advert-interval-cs"`
	// Preempt lets a higher-priority backup take over a lower-priority
	// master (§6.1: the RFC default is true).
	Preempt *bool `yaml:"preempt" json:"preempt" mapstructure:"preempt"`
	// AcceptMode makes the master answer packets addressed to the virtual
	// addresses it does not own (§6.1).
	AcceptMode bool `yaml:"accept-mode" json:"accept_mode" mapstructure:"accept-mode"`
	// Addresses are the virtual addresses with their prefix length, all of
	// one family (e.g. 198.18.0.1/24, 2602:f5bb::1/64).
	Addresses []string `yaml:"addresses" json:"addresses" mapstructure:"addresses"`
	// Source is the interface address advertisements are sent from and the
	// tie-breaker of §6.4.3 ("sender's primary IP address"). It must be an
	// address of Interface in the group's family.
	Source string `yaml:"source" json:"source" mapstructure:"source"`
}

// Validate checks one group and reports the first defect.
func (g GroupConfig) Validate() error {
	if g.VRID == 0 {
		return &ErrInvalidGroupConfig{VRID: g.VRID, Field: "vrid", Reason: "must be 1-255"}
	}
	if strings.TrimSpace(g.Interface) == "" {
		return &ErrInvalidGroupConfig{VRID: g.VRID, Field: "interface", Reason: "is required"}
	}
	if g.AdvertIntervalCentiseconds > MaxAdvertIntervalCentiseconds {
		return &ErrInvalidGroupConfig{VRID: g.VRID, Field: "advert-interval-cs", Reason: "exceeds 4095"}
	}
	if len(g.Addresses) == 0 {
		return &ErrInvalidGroupConfig{VRID: g.VRID, Field: "addresses", Reason: "at least one is required"}
	}
	var fam Family
	for _, raw := range g.Addresses {
		pfx, err := netip.ParsePrefix(raw)
		if err != nil {
			return &ErrInvalidGroupConfig{VRID: g.VRID, Field: "addresses", Reason: "entry " + raw + " is not an address/prefix"}
		}
		if pfx.Addr().IsUnspecified() || pfx.Addr().IsMulticast() || pfx.Addr().IsLoopback() {
			return &ErrInvalidGroupConfig{VRID: g.VRID, Field: "addresses", Reason: "entry " + raw + " is not a usable unicast address"}
		}
		f := FamilyIPv4
		if pfx.Addr().Is6() {
			f = FamilyIPv6
		}
		if fam == 0 {
			fam = f
		} else if fam != f {
			return &ErrInvalidGroupConfig{VRID: g.VRID, Field: "addresses", Reason: "mixes IPv4 and IPv6; use one group per family"}
		}
	}
	if strings.TrimSpace(g.Source) == "" {
		return &ErrInvalidGroupConfig{VRID: g.VRID, Field: "source", Reason: "is required"}
	}
	src, err := netip.ParseAddr(g.Source)
	if err != nil {
		return &ErrInvalidGroupConfig{VRID: g.VRID, Field: "source", Reason: "is not an IP address"}
	}
	if (fam == FamilyIPv6) != src.Is6() {
		return &ErrInvalidGroupConfig{VRID: g.VRID, Field: "source", Reason: "is not in the group's address family"}
	}
	return nil
}

// Validate checks the section: every group valid and no VRID configured
// twice on the same interface.
func (c Config) Validate() error {
	seen := map[string]bool{}
	for _, g := range c.Groups {
		if err := g.Validate(); err != nil {
			return err
		}
		key := g.Interface + "/" + string(rune(g.VRID)) + "/" + g.family().String()
		if seen[key] {
			return &ErrDuplicateGroup{VRID: g.VRID, Interface: g.Interface}
		}
		seen[key] = true
	}
	return nil
}

// family reports the group's address family; callers validate first.
func (g GroupConfig) family() Family {
	for _, raw := range g.Addresses {
		if pfx, err := netip.ParsePrefix(raw); err == nil && pfx.Addr().Is6() {
			return FamilyIPv6
		}
	}
	return FamilyIPv4
}

// effectivePriority applies the RFC default.
func (g GroupConfig) effectivePriority() uint8 {
	if g.Priority == 0 {
		return PriorityDefault
	}
	return g.Priority
}

// effectiveInterval applies the RFC default.
func (g GroupConfig) effectiveInterval() uint16 {
	if g.AdvertIntervalCentiseconds == 0 {
		return DefaultAdvertIntervalCentiseconds
	}
	return g.AdvertIntervalCentiseconds
}

// preempts applies the RFC default (true).
func (g GroupConfig) preempts() bool {
	return g.Preempt == nil || *g.Preempt
}

// prefixes returns the parsed virtual addresses; callers validate first.
func (g GroupConfig) prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(g.Addresses))
	for _, raw := range g.Addresses {
		if pfx, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, pfx)
		}
	}
	return out
}

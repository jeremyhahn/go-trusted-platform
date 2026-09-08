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

package bgp

import "net/netip"

// AnnounceConfig holds prefixes to announce via BGP.
// IPv4Prefixes and IPv6Prefixes are CIDR strings representing the
// network blocks owned by this AS that should be advertised to peers.
type AnnounceConfig struct {
	// IPv4Prefixes is the list of IPv4 CIDR prefixes to announce (e.g., "23.143.36.0/24").
	IPv4Prefixes []string `yaml:"ipv4" json:"ipv4" mapstructure:"ipv4"`

	// IPv6Prefixes is the list of IPv6 CIDR prefixes to announce (e.g., "2602:F5BB::/36").
	IPv6Prefixes []string `yaml:"ipv6" json:"ipv6" mapstructure:"ipv6"`
}

// Validate checks that all configured prefixes are valid CIDR notation.
func (a *AnnounceConfig) Validate() error {
	for _, p := range a.IPv4Prefixes {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return &ErrPrefixInvalid{Reason: err.Error()}
		}
		if !prefix.Addr().Is4() {
			return ErrIPv4Required
		}
	}
	for _, p := range a.IPv6Prefixes {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return &ErrPrefixInvalid{Reason: err.Error()}
		}
		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return ErrIPv6Required
		}
	}
	return nil
}

// AllPrefixes returns all configured prefixes as parsed netip.Prefix values.
func (a *AnnounceConfig) AllPrefixes() ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(a.IPv4Prefixes)+len(a.IPv6Prefixes))
	for _, p := range a.IPv4Prefixes {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, &ErrPrefixInvalid{Reason: err.Error()}
		}
		result = append(result, prefix)
	}
	for _, p := range a.IPv6Prefixes {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, &ErrPrefixInvalid{Reason: err.Error()}
		}
		result = append(result, prefix)
	}
	return result, nil
}

// HasPrefixes returns true if any prefixes are configured for announcement.
func (a *AnnounceConfig) HasPrefixes() bool {
	return len(a.IPv4Prefixes) > 0 || len(a.IPv6Prefixes) > 0
}

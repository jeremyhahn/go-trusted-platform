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

import "net/netip"

// Default policy values for the conntrack verdict table miss.
const (
	// PolicyAllow continues the pipeline for connections no matrix rule
	// matched.
	PolicyAllow = "allow"

	// PolicyDeny drops connections no matrix rule matched.
	PolicyDeny = "deny"
)

// Config is the firewall service configuration. The gateway maps its
// serialized FirewallConfig section onto this struct; the firewall package
// deliberately owns its own type so it never imports the gateway package
// that composes it.
type Config struct {
	// DefaultPolicy is the conntrack verdict table-miss behavior:
	// PolicyAllow or PolicyDeny.
	DefaultPolicy string

	// Bridge is the OVS bridge carrying the ct pipeline.
	Bridge string
}

// Validate checks the firewall configuration.
func (c *Config) Validate() error {
	if c.DefaultPolicy != PolicyAllow && c.DefaultPolicy != PolicyDeny {
		return ErrInvalidDefaultPolicy
	}
	if c.Bridge == "" {
		return ErrEmptyBridge
	}
	return nil
}

// NATConfig is the NAT service configuration, mapped from the gateway's
// serialized NATConfig section plus the uplink port name.
type NATConfig struct {
	// ExternalIP is the public IPv4 address SNAT translates to and DNAT
	// rules accept traffic on.
	ExternalIP string

	// PortRangeStart is the first L4 port SNAT may allocate.
	PortRangeStart uint16

	// PortRangeEnd is the last L4 port SNAT may allocate.
	PortRangeEnd uint16

	// InternalCIDR is the IPv4 prefix whose egress traffic is source-NATed.
	// Empty disables automatic SNAT on Start.
	InternalCIDR string

	// UplinkPort is the OVS port name of the uplink; DNAT rules match
	// ingress on this port. Empty disables DNAT.
	UplinkPort string

	// Bridge is the OVS bridge carrying the NAT tables.
	Bridge string
}

// Validate checks the NAT configuration and returns the parsed external
// address and optional internal prefix.
func (c *NATConfig) Validate() (netip.Addr, netip.Prefix, error) {
	external, err := netip.ParseAddr(c.ExternalIP)
	if err != nil || !external.Is4() {
		return netip.Addr{}, netip.Prefix{}, ErrInvalidExternalIP
	}
	if c.PortRangeStart == 0 || c.PortRangeStart >= c.PortRangeEnd {
		return netip.Addr{}, netip.Prefix{}, ErrInvalidPortRange
	}
	if c.Bridge == "" {
		return netip.Addr{}, netip.Prefix{}, ErrEmptyBridge
	}

	var internal netip.Prefix
	if c.InternalCIDR != "" {
		internal, err = netip.ParsePrefix(c.InternalCIDR)
		if err != nil || !internal.Addr().Is4() {
			return netip.Addr{}, netip.Prefix{}, ErrInvalidInternalCIDR
		}
	}

	return external, internal, nil
}

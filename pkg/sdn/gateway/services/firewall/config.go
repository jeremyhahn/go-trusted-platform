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
	"fmt"
	"net/netip"
	"strings"
)

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
	// ingress on this port. Empty disables DNAT. Ignored when Uplinks is
	// set — each uplink then names its own port.
	UplinkPort string

	// Bridge is the OVS bridge carrying the NAT tables.
	Bridge string

	// Uplinks, when set, replaces ExternalIP with one SNAT pool per uplink
	// (#586). Egress from InternalCIDR is translated to the pool of the
	// uplink it leaves through: the default uplink unless a destination
	// prefix of another uplink matches. Exactly one uplink is the default
	// (the first when none is marked).
	Uplinks []NATUplink

	// Static are the 1:1 address translations: External on an uplink is
	// Internal inside, in both directions, with hairpin for internal
	// clients addressing External (#586).
	Static []StaticNAT
}

// NATUplink is one SNAT pool bound to an uplink.
type NATUplink struct {
	// Name identifies the uplink; it matches the gateway's uplink name.
	Name string

	// Port is the OVS port name of the uplink. Empty means Name.
	Port string

	// Addresses is the IPv4 pool SNAT translates to on this uplink: single
	// addresses ("203.0.113.10") or inclusive ranges
	// ("203.0.113.10-203.0.113.14"). At least one is required.
	Addresses []string

	// PortRangeStart and PortRangeEnd bound the L4 ports SNAT may allocate
	// on this uplink. Zero takes the NATConfig-wide range.
	PortRangeStart uint16
	PortRangeEnd   uint16

	// Destinations are IPv4 prefixes whose traffic leaves through this
	// uplink regardless of the default — the uplink-selection hook that
	// mirrors the platform's per-uplink routing tables. Optional.
	Destinations []string

	// Default marks the uplink that carries every destination no other
	// uplink claims.
	Default bool
}

// StaticNAT is one 1:1 translation.
type StaticNAT struct {
	// Internal is the inside IPv4 address.
	Internal string

	// External is the public IPv4 address, reachable on Uplink.
	External string

	// Uplink names the NATUplink the external address is reachable on.
	// Empty means the default uplink.
	Uplink string
}

// natPool is a validated SNAT pool: an inclusive IPv4 range and a port
// range, rendered in OVS nat(src=...) syntax.
type natPool struct {
	first, last netip.Addr
	portStart   uint16
	portEnd     uint16
}

func (p natPool) String() string {
	addr := p.first.String()
	if p.last != p.first {
		addr += "-" + p.last.String()
	}
	return fmt.Sprintf("%s:%d-%d", addr, p.portStart, p.portEnd)
}

// natUplink is a validated NATUplink.
type natUplink struct {
	name         string
	port         string
	pools        []natPool
	destinations []netip.Prefix
	isDefault    bool
}

// natStatic is a validated StaticNAT.
type natStatic struct {
	internal netip.Addr
	external netip.Addr
	uplink   string
}

// natPlan is the validated multi-uplink shape of a NATConfig: the uplinks in
// configuration order (their index is the reg0 selector value minus one),
// the default uplink's index, and the static translations.
type natPlan struct {
	uplinks    []natUplink
	defaultIdx int
	statics    []natStatic
}

// uplinkFor returns the uplink whose pools or statics contain addr, or the
// default uplink.
func (p *natPlan) uplinkFor(addr netip.Addr) natUplink {
	for _, u := range p.uplinks {
		for _, pool := range u.pools {
			if addr.Compare(pool.first) >= 0 && addr.Compare(pool.last) <= 0 {
				return u
			}
		}
	}
	for _, st := range p.statics {
		if st.external == addr {
			return p.byName(st.uplink)
		}
	}
	return p.uplinks[p.defaultIdx]
}

// byName returns the named uplink, or the default when the name is empty
// or unknown (validation guarantees statics name a real uplink).
func (p *natPlan) byName(name string) natUplink {
	for _, u := range p.uplinks {
		if u.name == name {
			return u
		}
	}
	return p.uplinks[p.defaultIdx]
}

// plan validates the multi-uplink configuration. A NATConfig with no
// Uplinks yields a nil plan and the single-address behaviour.
func (c *NATConfig) plan() (*natPlan, error) {
	if len(c.Uplinks) == 0 {
		if len(c.Static) > 0 {
			return nil, ErrStaticNeedsUplink
		}
		return nil, nil
	}
	plan := &natPlan{defaultIdx: -1}
	seen := make(map[string]struct{}, len(c.Uplinks))
	for i, in := range c.Uplinks {
		if in.Name == "" {
			return nil, &ErrInvalidNATUplink{Index: i, Reason: "name is required"}
		}
		if _, dup := seen[in.Name]; dup {
			return nil, &ErrInvalidNATUplink{Index: i, Name: in.Name, Reason: "duplicate name"}
		}
		seen[in.Name] = struct{}{}
		if len(in.Addresses) == 0 {
			return nil, &ErrInvalidNATUplink{Index: i, Name: in.Name, Reason: "at least one pool address is required"}
		}
		start, end := in.PortRangeStart, in.PortRangeEnd
		if start == 0 && end == 0 {
			start, end = c.PortRangeStart, c.PortRangeEnd
		}
		if start == 0 || start >= end {
			return nil, &ErrInvalidNATUplink{Index: i, Name: in.Name, Reason: "port range start must be non-zero and below end"}
		}
		u := natUplink{name: in.Name, port: in.Port, isDefault: in.Default}
		if u.port == "" {
			u.port = in.Name
		}
		for _, a := range in.Addresses {
			pool, err := parsePool(a, start, end)
			if err != nil {
				return nil, &ErrInvalidNATUplink{Index: i, Name: in.Name, Reason: "pool " + a + ": " + err.Error()}
			}
			u.pools = append(u.pools, pool)
		}
		for _, d := range in.Destinations {
			pfx, err := netip.ParsePrefix(d)
			if err != nil || !pfx.Addr().Is4() {
				return nil, &ErrInvalidNATUplink{Index: i, Name: in.Name, Reason: "destination " + d + " is not an IPv4 prefix"}
			}
			u.destinations = append(u.destinations, pfx.Masked())
		}
		if in.Default {
			if plan.defaultIdx >= 0 {
				return nil, &ErrInvalidNATUplink{Index: i, Name: in.Name, Reason: "more than one default uplink"}
			}
			plan.defaultIdx = i
		}
		plan.uplinks = append(plan.uplinks, u)
	}
	if plan.defaultIdx < 0 {
		plan.defaultIdx = 0
		plan.uplinks[0].isDefault = true
	}
	externals := make(map[netip.Addr]struct{}, len(c.Static))
	for i, st := range c.Static {
		internal, err := netip.ParseAddr(st.Internal)
		if err != nil || !internal.Is4() {
			return nil, &ErrInvalidStaticNAT{Index: i, Reason: "internal must be an IPv4 address"}
		}
		external, err := netip.ParseAddr(st.External)
		if err != nil || !external.Is4() {
			return nil, &ErrInvalidStaticNAT{Index: i, Reason: "external must be an IPv4 address"}
		}
		if _, dup := externals[external]; dup {
			return nil, &ErrInvalidStaticNAT{Index: i, Reason: "external " + st.External + " is mapped twice"}
		}
		externals[external] = struct{}{}
		uplink := st.Uplink
		if uplink == "" {
			uplink = plan.uplinks[plan.defaultIdx].name
		} else if _, ok := seen[uplink]; !ok {
			return nil, &ErrInvalidStaticNAT{Index: i, Reason: "uplink " + uplink + " is not configured"}
		}
		plan.statics = append(plan.statics, natStatic{internal: internal, external: external, uplink: uplink})
	}
	return plan, nil
}

// parsePool parses "addr" or "first-last" into an inclusive IPv4 pool.
func parsePool(spec string, portStart, portEnd uint16) (natPool, error) {
	first, last, found := strings.Cut(spec, "-")
	if !found {
		last = first
	}
	a, err := netip.ParseAddr(strings.TrimSpace(first))
	if err != nil || !a.Is4() {
		return natPool{}, ErrInvalidExternalIP
	}
	b, err := netip.ParseAddr(strings.TrimSpace(last))
	if err != nil || !b.Is4() {
		return natPool{}, ErrInvalidExternalIP
	}
	if b.Less(a) {
		return natPool{}, ErrInvalidPoolRange
	}
	return natPool{first: a, last: b, portStart: portStart, portEnd: portEnd}, nil
}

// Validate checks the NAT configuration and returns the parsed external
// address and optional internal prefix.
func (c *NATConfig) Validate() (netip.Addr, netip.Prefix, error) {
	var external netip.Addr
	if len(c.Uplinks) == 0 || c.ExternalIP != "" {
		var err error
		external, err = netip.ParseAddr(c.ExternalIP)
		if err != nil || !external.Is4() {
			return netip.Addr{}, netip.Prefix{}, ErrInvalidExternalIP
		}
	}
	// The config-wide port range is the default for every uplink pool, so
	// it must be valid even in multi-uplink mode.
	if c.PortRangeStart == 0 || c.PortRangeStart >= c.PortRangeEnd {
		return netip.Addr{}, netip.Prefix{}, ErrInvalidPortRange
	}
	if _, err := c.plan(); err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	if c.Bridge == "" {
		return netip.Addr{}, netip.Prefix{}, ErrEmptyBridge
	}

	var internal netip.Prefix
	if c.InternalCIDR != "" {
		parsed, err := netip.ParsePrefix(c.InternalCIDR)
		internal = parsed
		if err != nil || !internal.Addr().Is4() {
			return netip.Addr{}, netip.Prefix{}, ErrInvalidInternalCIDR
		}
	}

	return external, internal, nil
}

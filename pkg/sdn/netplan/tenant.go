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

import "net/netip"

// CheckTenantSubnet checks a tenant's own (BYO) subnet against the plan. The
// subnet lives in the tenant's VRF and may overlap other tenants' subnets; it
// may not take an address the plan reserves in every VRF, any zone's IPv4 or
// IPv6 gateway or the service VIP pool, it must be unicast across the whole
// prefix (no overlap with nonUnicast), and it must leave room for the anycast
// gateway (RFC 9135) and a workload. The error is an ErrTenantSubnet naming
// the reason.
//
// The reserved ranges are checked before the unicast check so that a subnet
// over the link-local host-services address names that address.
func (p *Plan) CheckTenantSubnet(subnet netip.Prefix) error {
	refuse := func(reason string) error {
		return ErrTenantSubnet{Subnet: subnet, Reason: reason}
	}
	if !subnet.IsValid() {
		return refuse("is not a valid prefix")
	}
	if subnet != subnet.Masked() {
		return refuse("is not a network prefix")
	}
	addr := subnet.Addr()
	if (addr.Is4() && subnet.Bits() > 30) || (addr.Is6() && subnet.Bits() > 64) {
		return refuse("has no room for the anycast gateway and a workload")
	}
	for _, r := range p.reserved {
		if r.Overlaps(subnet) {
			return refuse("overlaps reserved " + r.String())
		}
	}
	for _, z := range p.zones {
		if !z.Subnet6.IsValid() {
			continue
		}
		gw, err := Gateway(z.Subnet6)
		if err != nil {
			continue
		}
		if r := netip.PrefixFrom(gw, 128); r.Overlaps(subnet) {
			return refuse("overlaps reserved " + r.String())
		}
	}
	if vips, ok := p.ranges[RangeServiceVIPs]; ok && vips.Overlaps(subnet) {
		return refuse("overlaps service-vips " + vips.String())
	}
	for _, x := range nonUnicast {
		if x.Overlaps(subnet) {
			return refuse("is not a unicast range: overlaps " + x.String())
		}
	}
	return nil
}

// nonUnicast lists the address space a tenant subnet may not overlap:
// this-network, loopback, link-local, multicast and reserved (class E) IPv4
// space, and the IPv6 unspecified, loopback, IPv4-mapped, link-local and
// multicast ranges.
var nonUnicast = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

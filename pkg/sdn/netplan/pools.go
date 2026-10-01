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
	"slices"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// RangeKind names one part of an environment's IPAM pool (the upper /17 of
// its /16).
type RangeKind string

const (
	// RangeTunnelP2P holds the /31 point-to-point links of tunnels and
	// transit peerings: <base>.E.128.0/22, 512 links. Its first /31 is the
	// gateway HA sync link and never allocatable.
	RangeTunnelP2P RangeKind = "tunnel-p2p"

	// RangeLoopbacks holds router and VTEP loopback /32s:
	// <base>.E.132.0/22, 1024 addresses.
	RangeLoopbacks RangeKind = "loopbacks"

	// RangeServiceVIPs holds the platform service VIPs: <base>.E.136.0/21,
	// 2048 addresses.
	RangeServiceVIPs RangeKind = "service-vips"

	// RangePlatformHosts holds the one platform-VRF address of each
	// attested host: <base>.E.144.0/20, 4096 hosts.
	RangePlatformHosts RangeKind = "platform-hosts"

	// RangeTenantDefault is the default pool tenant overlay subnets are
	// carved from: <base>.E.192.0/18, 64 /24s.
	RangeTenantDefault RangeKind = "tenant-default"
)

// rangeLayout is the fixed split of the IPAM /17: each range's third octet
// (relative to the environment's /16) and prefix length. <base>.E.160.0/19
// is left unallocated for growth.
var rangeLayout = []struct {
	kind  RangeKind
	third byte
	bits  int
}{
	{RangeTunnelP2P, 128, 22},
	{RangeLoopbacks, 132, 22},
	{RangeServiceVIPs, 136, 21},
	{RangePlatformHosts, 144, 20},
	{RangeTenantDefault, 192, 18},
}

// RangeKinds returns the IPAM range kinds in address order.
func RangeKinds() []RangeKind {
	out := make([]RangeKind, len(rangeLayout))
	for i, r := range rangeLayout {
		out[i] = r.kind
	}
	return out
}

// deriveRanges computes the IPAM ranges of environment e on base.
func deriveRanges(base netip.Prefix, e uint16) map[RangeKind]netip.Prefix {
	a := base.Addr().As4()
	out := make(map[RangeKind]netip.Prefix, len(rangeLayout))
	for _, r := range rangeLayout {
		out[r.kind] = netip.PrefixFrom(netip.AddrFrom4([4]byte{a[0], byte(e), r.third, 0}), r.bits)
	}
	return out
}

// Pool is one IPAM pool of the plan: the pool of a zone (its subnet, its
// gateway, and a DHCP range from .50) or one range of the IPAM /17.
type Pool struct {
	// Name is the pool name: the zone name, or the range kind.
	Name string
	// Zone is the zone of a zone pool; empty for a range pool.
	Zone zone.Zone
	// Range is the kind of a range pool; empty for a zone pool.
	Range RangeKind
	// Prefix is the pool's address space.
	Prefix netip.Prefix
	// Gateway is a zone pool's gateway address (.1); invalid for ranges.
	Gateway netip.Addr
	// Reserved lists the never-allocatable prefixes inside Prefix.
	Reserved []netip.Prefix
	// RangeStart and RangeEnd bound dynamic allocation (DHCP for a zone
	// pool). Both are invalid when the pool is too small for a dynamic
	// range (a zone subnet longer than /26).
	RangeStart netip.Addr
	RangeEnd   netip.Addr
}

// HasDynamicRange reports whether the pool has a dynamic (DHCP) range.
func (p Pool) HasDynamicRange() bool {
	return p.RangeStart.IsValid() && p.RangeEnd.IsValid()
}

// IPAMPool returns the environment's IPAM pool: the upper /17 of its /16.
func (p *Plan) IPAMPool() netip.Prefix {
	a := p.env.Base.Addr().As4()
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{a[0], byte(p.env.ID), 128, 0}), 17)
}

// Range returns the prefix of one IPAM range.
func (p *Plan) Range(kind RangeKind) (netip.Prefix, bool) {
	r, ok := p.ranges[kind]
	return r, ok
}

// GatewayHASync returns the /31 of the gateway HA sync link: the first /31
// of the tunnel point-to-point range (gateway node 0 takes the first
// address, node 1 the second). It is reserved, never allocatable.
func (p *Plan) GatewayHASync() netip.Prefix {
	return netip.PrefixFrom(p.ranges[RangeTunnelP2P].Addr(), 31)
}

// HostServices6 returns the reserved per-VRF host-services /64 inside the
// deployment ULA. ok is false when the environment has no ULA.
func (p *Plan) HostServices6() (netip.Prefix, bool) {
	if !p.env.ULA.IsValid() {
		return netip.Prefix{}, false
	}
	return subnet6WithID(p.env.ULA, hostServicesSubnetID), true
}

// ZonePool returns the IPAM pool of zone z.
func (p *Plan) ZonePool(z zone.Zone) (Pool, bool) {
	n, ok := p.Zone(z)
	if !ok {
		return Pool{}, false
	}
	return zonePool(n), true
}

// zonePool builds the pool of one zone.
func zonePool(n ZoneNumbering) Pool {
	pool := Pool{
		Name:     string(n.Zone),
		Zone:     n.Zone,
		Prefix:   n.Subnet4,
		Gateway:  n.Gateway,
		Reserved: []netip.Prefix{netip.PrefixFrom(n.Gateway, 32)},
	}
	start, err := Host(n.Subnet4, HostDHCPFirst)
	if err != nil {
		return pool
	}
	end := lastAddr(n.Subnet4).Prev()
	if end.Less(start) {
		return pool
	}
	pool.RangeStart = start
	pool.RangeEnd = end
	return pool
}

// RangePool returns the IPAM pool of one range of the IPAM /17.
func (p *Plan) RangePool(kind RangeKind) (Pool, bool) {
	prefix, ok := p.ranges[kind]
	if !ok {
		return Pool{}, false
	}
	pool := Pool{
		Name:       string(kind),
		Range:      kind,
		Prefix:     prefix,
		RangeStart: prefix.Addr(),
		RangeEnd:   lastAddr(prefix),
	}
	if kind == RangeTunnelP2P {
		pool.Reserved = []netip.Prefix{p.GatewayHASync()}
		pool.RangeStart = addAddr(prefix.Addr(), 2)
	}
	return pool, true
}

// Pools returns the pools the platform seeds into IPAM: one per zone (in
// zone order), then one per IPAM range (in address order) except the tenant
// default range. That range is not one pool: tenant overlay subnets are
// carved from it, each as a pool of its own.
func (p *Plan) Pools() []Pool {
	out := make([]Pool, 0, len(p.zones)+len(rangeLayout))
	for _, n := range p.zones {
		out = append(out, zonePool(n))
	}
	for _, r := range rangeLayout {
		if r.kind == RangeTenantDefault {
			continue
		}
		pool, _ := p.RangePool(r.kind)
		out = append(out, pool)
	}
	return out
}

// deriveReserved lists the never-allocatable ranges: the gateway HA sync
// /31, the host-services address and /64, and every zone gateway address.
func (p *Plan) deriveReserved() []netip.Prefix {
	out := []netip.Prefix{
		p.GatewayHASync(),
		netip.PrefixFrom(HostServices4, 32),
	}
	if hs6, ok := p.HostServices6(); ok {
		out = append(out, hs6)
	}
	for _, z := range p.zones {
		out = append(out, netip.PrefixFrom(z.Gateway, 32))
	}
	return out
}

// Reserved returns the never-allocatable ranges of the plan.
func (p *Plan) Reserved() []netip.Prefix {
	return slices.Clone(p.reserved)
}

// IsReserved reports whether a lies in one of the plan's reserved ranges.
// The anycast gateway of an overlay subnet carved later is reserved by the
// pool that subnet is created with (see AnycastGateway).
func (p *Plan) IsReserved(a netip.Addr) bool {
	a = a.Unmap()
	for _, r := range p.reserved {
		if r.Contains(a) {
			return true
		}
	}
	return false
}

// AnycastGateway returns the distributed anycast gateway address of an
// overlay subnet (RFC 9135): its first host address, which is reserved in
// every subnet and never handed to a workload.
func AnycastGateway(subnet netip.Prefix) (netip.Addr, error) {
	return Gateway(subnet)
}

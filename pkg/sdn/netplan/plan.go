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

// ZoneNumbering is the derived (or overridden) numbering of one zone.
type ZoneNumbering struct {
	// Zone is the zone name.
	Zone zone.Zone
	// Offset is the zone's offset in the environment block.
	Offset zone.Offset
	// VLAN is the zone's VLAN ID.
	VLAN uint16
	// Subnet4 is the zone's IPv4 subnet.
	Subnet4 netip.Prefix
	// Subnet6 is the zone's IPv6 /64; invalid when the environment has no
	// ULA and no override sets one.
	Subnet6 netip.Prefix
	// Gateway is the zone's gateway address (.1).
	Gateway netip.Addr
	// PortClasses are the switch port classes that carry the zone.
	PortClasses []zone.PortClass
}

// Plan is the numbering of one environment: every zone's VLAN and subnets,
// its IPAM pools, the reserved ranges and the port-class VLAN lists. A Plan
// is immutable and safe for concurrent use.
type Plan struct {
	env      Environment
	zones    []ZoneNumbering
	byName   map[zone.Zone]int
	byVLAN   map[uint16]zone.Zone
	ranges   map[RangeKind]netip.Prefix
	reserved []netip.Prefix
}

// linkLocal4 is the IPv4 link-local space; no zone may live in it.
var linkLocal4 = netip.MustParsePrefix("169.254.0.0/16")

// New derives the plan of env for the resolved zone set (the output of
// zone.Resolve, already validated by zone.Validate). It fails when the
// environment is invalid, an override names an undeclared zone, or the
// numbers collide: two zones on one VLAN, overlapping subnets, or a zone
// inside the IPAM pool or a reserved range.
func New(env Environment, zones []zone.ZoneConfig) (*Plan, error) {
	if err := env.Validate(); err != nil {
		return nil, err
	}
	env.Base = env.EffectiveBase()

	declared := make(map[zone.Zone]struct{}, len(zones))
	for _, z := range zones {
		declared[z.Name] = struct{}{}
	}
	for _, o := range env.Overrides {
		if _, ok := declared[o.Zone]; !ok {
			return nil, ErrOverride{Zone: o.Zone, Reason: "the zone is not declared"}
		}
	}

	p := &Plan{
		env:    env,
		zones:  make([]ZoneNumbering, 0, len(zones)),
		byName: make(map[zone.Zone]int, len(zones)),
		byVLAN: make(map[uint16]zone.Zone, len(zones)),
		ranges: deriveRanges(env.Base, env.ID),
	}

	for _, z := range zones {
		n, err := p.number(z)
		if err != nil {
			return nil, err
		}
		if other, dup := p.byVLAN[n.VLAN]; dup {
			return nil, ErrDuplicateVLAN{VLAN: n.VLAN, Zones: [2]zone.Zone{other, n.Zone}}
		}
		p.byVLAN[n.VLAN] = n.Zone
		p.byName[n.Zone] = len(p.zones)
		p.zones = append(p.zones, n)
	}

	if err := p.checkOverlaps(); err != nil {
		return nil, err
	}
	p.reserved = p.deriveReserved()
	return p, nil
}

// number derives (or applies the override to) one zone's numbering.
func (p *Plan) number(z zone.ZoneConfig) (ZoneNumbering, error) {
	n := ZoneNumbering{
		Zone:        z.Name,
		Offset:      z.Offset,
		PortClasses: slices.Clone(z.PortClasses),
	}
	o, overridden := p.env.override(z.Name)

	vlan, err := VLAN(p.env.ID, z.Offset)
	switch {
	case overridden && o.VLAN != 0:
		n.VLAN = o.VLAN
	case err != nil:
		if e, ok := err.(ErrVLANOutOfRange); ok {
			e.Zone = z.Name
			return ZoneNumbering{}, e
		}
		return ZoneNumbering{}, err
	default:
		n.VLAN = vlan
	}

	if overridden && o.Subnet.IsValid() {
		n.Subnet4 = o.Subnet
	} else {
		s, err := Subnet4(p.env.Base, p.env.ID, z.Offset)
		if err != nil {
			return ZoneNumbering{}, err
		}
		n.Subnet4 = s
	}

	switch {
	case overridden && o.Subnet6.IsValid():
		n.Subnet6 = o.Subnet6
	case p.env.ULA.IsValid() && err == nil:
		// The IPv6 subnet follows the reference VLAN digits, so a VLAN
		// override does not move the zone's IPv6 subnet.
		s, err := Subnet6(p.env.ULA, vlan)
		if err != nil {
			return ZoneNumbering{}, err
		}
		n.Subnet6 = s
	}

	gw, err := Gateway(n.Subnet4)
	if err != nil {
		return ZoneNumbering{}, err
	}
	n.Gateway = gw
	return n, nil
}

// checkOverlaps refuses zone subnets that overlap each other, the IPAM
// pool, the IPv4 link-local space or the host-services /64.
func (p *Plan) checkOverlaps() error {
	ipam := p.IPAMPool()
	hs6, hasHS6 := p.HostServices6()
	for i, a := range p.zones {
		if a.Subnet4.Overlaps(ipam) {
			return ErrOverlap{Zone: a.Zone, Subnet: a.Subnet4, Other: "the IPAM pool " + ipam.String()}
		}
		if a.Subnet4.Overlaps(linkLocal4) {
			return ErrOverlap{Zone: a.Zone, Subnet: a.Subnet4, Other: "the link-local space " + linkLocal4.String()}
		}
		if hasHS6 && a.Subnet6.IsValid() && a.Subnet6.Overlaps(hs6) {
			return ErrOverlap{Zone: a.Zone, Subnet: a.Subnet6, Other: "the host-services prefix " + hs6.String()}
		}
		for _, b := range p.zones[i+1:] {
			if a.Subnet4.Overlaps(b.Subnet4) {
				return ErrOverlap{Zone: b.Zone, Subnet: b.Subnet4, Other: "zone " + string(a.Zone) + " " + a.Subnet4.String()}
			}
			if a.Subnet6.IsValid() && b.Subnet6.IsValid() && a.Subnet6.Overlaps(b.Subnet6) {
				return ErrOverlap{Zone: b.Zone, Subnet: b.Subnet6, Other: "zone " + string(a.Zone) + " " + a.Subnet6.String()}
			}
		}
	}
	return nil
}

// Environment returns the environment the plan was derived from, with the
// effective base filled in.
func (p *Plan) Environment() Environment {
	env := p.env
	env.Overrides = slices.Clone(p.env.Overrides)
	return env
}

// Zones returns the numbering of every zone, in the order of the zone set
// (built-ins by offset, then owner-defined zones by offset).
func (p *Plan) Zones() []ZoneNumbering {
	out := make([]ZoneNumbering, len(p.zones))
	for i, z := range p.zones {
		out[i] = z
		out[i].PortClasses = slices.Clone(z.PortClasses)
	}
	return out
}

// Zone returns the numbering of zone z.
func (p *Plan) Zone(z zone.Zone) (ZoneNumbering, bool) {
	i, ok := p.byName[z]
	if !ok {
		return ZoneNumbering{}, false
	}
	n := p.zones[i]
	n.PortClasses = slices.Clone(n.PortClasses)
	return n, true
}

// MustZone returns the numbering of zone z or ErrUnknownZone.
func (p *Plan) MustZone(z zone.Zone) (ZoneNumbering, error) {
	n, ok := p.Zone(z)
	if !ok {
		return ZoneNumbering{}, ErrUnknownZone{Zone: z}
	}
	return n, nil
}

// ZoneForVLAN returns the zone on VLAN v.
func (p *Plan) ZoneForVLAN(v uint16) (zone.Zone, bool) {
	z, ok := p.byVLAN[v]
	return z, ok
}

// ZoneForAddr returns the zone whose IPv4 or IPv6 subnet holds a.
func (p *Plan) ZoneForAddr(a netip.Addr) (zone.Zone, bool) {
	a = a.Unmap()
	for _, z := range p.zones {
		if z.Subnet4.Contains(a) || (z.Subnet6.IsValid() && z.Subnet6.Contains(a)) {
			return z.Zone, true
		}
	}
	return "", false
}

// VNI returns the VNI of overlay network n in this environment.
func (p *Plan) VNI(n uint32) (uint32, error) {
	return VNI(p.env.ID, n)
}

// OwnsVNI reports whether vni belongs to this environment, and returns its
// overlay network number.
func (p *Plan) OwnsVNI(vni uint32) (uint32, bool) {
	e, n, ok := SplitVNI(vni)
	if !ok || e != p.env.ID {
		return 0, false
	}
	return n, true
}

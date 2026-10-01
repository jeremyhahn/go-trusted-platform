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
	"slices"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// PortMode is the 802.1Q mode of a switch port class.
type PortMode string

const (
	// PortModeAccess carries one VLAN untagged.
	PortModeAccess PortMode = "access"
	// PortModeTrunk carries a list of tagged VLANs, optionally with a
	// native (untagged) VLAN.
	PortModeTrunk PortMode = "trunk"
)

// PortClassPlan is what a switch port of one class carries in this plan.
type PortClassPlan struct {
	// Class is the port class.
	Class zone.PortClass
	// Mode is access or trunk.
	Mode PortMode
	// Allowed is the sorted list of VLANs the port carries. For an access
	// port it holds the single access VLAN.
	Allowed []uint16
	// Native is the trunk's native VLAN; zero when the trunk has none. For
	// an access port it is the access VLAN.
	Native uint16
	// MTU is the port MTU.
	MTU int
}

// portClassModes fixes the mode of every port class. The hypervisor trunk
// is the only class with a native VLAN (provisioning).
var portClassModes = map[zone.PortClass]PortMode{
	zone.PortClassGateway:    PortModeTrunk,
	zone.PortClassHypervisor: PortModeTrunk,
	zone.PortClassBMC:        PortModeAccess,
	zone.PortClassMgmtUplink: PortModeTrunk,
	zone.PortClassPeerLink:   PortModeTrunk,
}

// PortClasses returns every port class, in a fixed order.
func PortClasses() []zone.PortClass {
	return []zone.PortClass{
		zone.PortClassGateway,
		zone.PortClassHypervisor,
		zone.PortClassBMC,
		zone.PortClassMgmtUplink,
		zone.PortClassPeerLink,
	}
}

// PortClass returns what a port of class c carries: the VLANs of the zones
// that are members of c (every zone for the peer-link), the native VLAN of
// the hypervisor trunk (provisioning), and MTU 9216.
func (p *Plan) PortClass(c zone.PortClass) (PortClassPlan, error) {
	mode, ok := portClassModes[c]
	if !ok {
		return PortClassPlan{}, ErrUnknownPortClass{Class: c}
	}
	out := PortClassPlan{Class: c, Mode: mode, MTU: MTU}
	for _, z := range p.zones {
		if c == zone.PortClassPeerLink || slices.Contains(z.PortClasses, c) {
			out.Allowed = append(out.Allowed, z.VLAN)
		}
	}
	if len(out.Allowed) == 0 {
		return PortClassPlan{}, ErrEmptyPortClass{Class: c}
	}
	slices.Sort(out.Allowed)

	switch {
	case mode == PortModeAccess:
		out.Allowed = out.Allowed[:1]
		out.Native = out.Allowed[0]
	case c == zone.PortClassHypervisor:
		prov, ok := p.Zone(zone.ZoneProvisioning)
		if !ok {
			return PortClassPlan{}, ErrUnknownZone{Zone: zone.ZoneProvisioning}
		}
		out.Native = prov.VLAN
	}
	return out, nil
}

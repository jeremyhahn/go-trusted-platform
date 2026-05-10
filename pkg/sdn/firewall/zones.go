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

// Zone defines a named network zone with its member interfaces and
// default traffic policy.
type Zone struct {
	// Name is the unique zone identifier.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// Interfaces is the list of network interface names in this zone.
	Interfaces []string `yaml:"interfaces" json:"interfaces" mapstructure:"interfaces"`

	// Policy is the default action for traffic originating from this zone.
	// Must be "allow" or "deny".
	Policy string `yaml:"policy" json:"policy" mapstructure:"policy"`
}

// ZoneResolver maps network interfaces to their containing zones.
type ZoneResolver struct {
	zones    map[string]*Zone
	ifToZone map[string]string
}

// NewZoneResolver creates a zone resolver from the given zone definitions.
func NewZoneResolver(zones []Zone) *ZoneResolver {
	zr := &ZoneResolver{
		zones:    make(map[string]*Zone, len(zones)),
		ifToZone: make(map[string]string),
	}
	for i := range zones {
		z := &zones[i]
		zr.zones[z.Name] = z
		for _, iface := range z.Interfaces {
			zr.ifToZone[iface] = z.Name
		}
	}
	return zr
}

// ZoneForInterface returns the zone name for the given interface.
// The second return value is false if no zone contains the interface.
func (zr *ZoneResolver) ZoneForInterface(iface string) (string, bool) {
	name, ok := zr.ifToZone[iface]
	return name, ok
}

// Zone returns the zone definition for the given name.
// The second return value is false if the zone does not exist.
func (zr *ZoneResolver) Zone(name string) (*Zone, bool) {
	z, ok := zr.zones[name]
	return z, ok
}

// PolicyForZone returns the default action for the named zone.
// Returns ActionDeny if the zone is not found.
func (zr *ZoneResolver) PolicyForZone(name string) Action {
	z, ok := zr.zones[name]
	if !ok {
		return ActionDeny
	}
	return parseAction(z.Policy)
}

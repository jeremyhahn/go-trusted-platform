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

package sdn

import (
	"fmt"
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ErrBuildZoneIndex is returned when the ZoneIndex cannot be built due to
// a configuration inconsistency detected during index construction.
type ErrBuildZoneIndex struct {
	// Cause describes what went wrong.
	Cause error
}

// Error implements the error interface.
func (e ErrBuildZoneIndex) Error() string {
	return fmt.Sprintf("sdn: build zone index: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrBuildZoneIndex) Unwrap() error { return e.Cause }

// ZoneIndex provides O(1) lookups from VLAN ID, subnet address, and zone name
// to the associated NetworkConfig entries. It is built once at config load
// time via BuildZoneIndex and is safe for concurrent reads.
type ZoneIndex struct {
	// byZone maps each zone to the set of networks classified under it.
	byZone map[zone.Zone][]NetworkConfig

	// byVLAN maps VLAN ID → zone for all networks that declare a VLAN.
	byVLAN map[uint16]zone.Zone

	// bySubnet maps exact prefix → zone for all networks that declare a Subnet.
	// The containment scan in ZoneForSubnet iterates this map, so it must
	// remain small (typical deployments have O(10) networks).
	bySubnet map[netip.Prefix]zone.Zone

	// byName maps network name → NetworkConfig.
	byName map[string]NetworkConfig
}

// BuildZoneIndex constructs a ZoneIndex from the supplied zones and network
// list. Both slices must already be validated; BuildZoneIndex does not
// re-validate them but does return an error on structural inconsistencies
// (e.g. a network referencing a zone that has no entry in zones).
func BuildZoneIndex(zones []zone.ZoneConfig, networks []NetworkConfig) (*ZoneIndex, error) {
	// Build a quick set of declared zone names for membership checks.
	zoneSet := make(map[zone.Zone]struct{}, len(zones))
	for _, z := range zones {
		zoneSet[z.Name] = struct{}{}
	}

	idx := &ZoneIndex{
		byZone:   make(map[zone.Zone][]NetworkConfig, len(zones)),
		byVLAN:   make(map[uint16]zone.Zone, len(networks)),
		bySubnet: make(map[netip.Prefix]zone.Zone, len(networks)),
		byName:   make(map[string]NetworkConfig, len(networks)),
	}

	// Pre-populate byZone keys so every declared zone has an (empty) slice.
	for _, z := range zones {
		idx.byZone[z.Name] = nil
	}

	for _, n := range networks {
		if n.Zone != "" {
			if _, ok := zoneSet[n.Zone]; !ok {
				return nil, ErrBuildZoneIndex{
					Cause: &MessageError{Msg: fmt.Sprintf("network %q references undeclared zone %q", n.Name, n.Zone)},
				}
			}
			idx.byZone[n.Zone] = append(idx.byZone[n.Zone], n)
		}
		if n.VLAN > 0 {
			idx.byVLAN[n.VLAN] = n.Zone
		}
		if n.Subnet.IsValid() {
			idx.bySubnet[n.Subnet] = n.Zone
		}
		idx.byName[n.Name] = n
	}

	return idx, nil
}

// ByZone returns all NetworkConfig entries classified under z. The returned
// slice is a copy; callers may not modify it. Returns nil when the zone is
// not in the index.
func (idx *ZoneIndex) ByZone(z zone.Zone) []NetworkConfig {
	if idx == nil {
		return nil
	}
	nets := idx.byZone[z]
	if len(nets) == 0 {
		return nil
	}
	out := make([]NetworkConfig, len(nets))
	copy(out, nets)
	return out
}

// ZoneForVLAN returns the zone associated with vlanID, or (zero, false) when
// no network with that VLAN is in the index.
func (idx *ZoneIndex) ZoneForVLAN(vlanID uint16) (zone.Zone, bool) {
	if idx == nil {
		return "", false
	}
	z, ok := idx.byVLAN[vlanID]
	return z, ok
}

// ZoneForSubnet returns the zone whose declared Subnet prefix contains addr.
// The lookup performs exact-prefix containment: it iterates the index's subnet
// map and returns the zone of the first prefix that contains addr. For the
// small N typical in platform deployments this linear scan is fast enough;
// when N grows a radix trie can replace the map without changing the API.
//
// Returns (zero, false) when no registered prefix contains addr.
func (idx *ZoneIndex) ZoneForSubnet(addr netip.Addr) (zone.Zone, bool) {
	if idx == nil {
		return "", false
	}
	for prefix, z := range idx.bySubnet {
		if prefix.Contains(addr) {
			return z, true
		}
	}
	return "", false
}

// NetworkByName returns the NetworkConfig registered under name, or (zero,
// false) when no network with that name exists.
func (idx *ZoneIndex) NetworkByName(name string) (NetworkConfig, bool) {
	if idx == nil {
		return NetworkConfig{}, false
	}
	n, ok := idx.byName[name]
	return n, ok
}

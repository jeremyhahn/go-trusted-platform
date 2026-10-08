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

import (
	"net/netip"
	"strconv"

	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Route distinguishers and route targets of the overlay (RFC 7432 §7.9,
// RFC 8365 §5.1.2.1).
const (
	// MinVNI is the minimum valid VNI value.
	MinVNI uint32 = 1

	// MaxVNI is the maximum valid VNI value: a VNI is 24 bits and travels
	// in the 24-bit label field unshifted (RFC 8365 §5.1.3).
	MaxVNI uint32 = 1<<24 - 1

	// MinOverlayASN and MaxOverlayASN bound the private 2-octet ASN the
	// overlay route targets are derived from (RFC 6996).
	MinOverlayASN uint16 = 64512
	MaxOverlayASN uint16 = 65534

	// MaxDomainID is the largest D-ID, the 4-bit site field of an
	// auto-derived route target.
	MaxDomainID uint8 = 15

	// autoRTTypeVXLAN is the 3-bit Type field of an auto-derived route
	// target for a VXLAN service.
	autoRTTypeVXLAN = 1
)

// RouteDistinguisher is the Type-1 route distinguisher RFC 7432 §7.9
// requires of every EVPN route: the originator's IPv4 address and a 16-bit
// number unique on that originator per EVI or IP-VRF.
type RouteDistinguisher struct {
	Admin netip.Addr
	Index uint16
}

// String returns the RD as "address:index".
func (rd RouteDistinguisher) String() string {
	return rd.Admin.String() + ":" + strconv.FormatUint(uint64(rd.Index), 10)
}

// native returns the GoBGP form of the RD.
func (rd RouteDistinguisher) native() (gobgp.RouteDistinguisherInterface, error) {
	if !rd.Admin.Is4() {
		return nil, ErrInvalidRouteDistinguisher{RD: rd.String(), Reason: "the administrator of a Type-1 RD is an IPv4 address"}
	}
	native, err := gobgp.NewRouteDistinguisherIPAddressAS(rd.Admin, rd.Index)
	if err != nil {
		return nil, ErrInvalidRouteDistinguisher{RD: rd.String(), Reason: err.Error()}
	}
	return native, nil
}

// routeDistinguisherFromNative converts a received RD. Anything but Type-1
// is refused: RFC 7432 §7.9 allows no other type on an EVPN route.
func routeDistinguisherFromNative(rd gobgp.RouteDistinguisherInterface) (RouteDistinguisher, error) {
	typed, ok := rd.(*gobgp.RouteDistinguisherIPAddressAS)
	if !ok || typed == nil {
		reason := "not a Type-1 route distinguisher"
		if rd == nil {
			return RouteDistinguisher{}, ErrInvalidRouteDistinguisher{Reason: reason}
		}
		return RouteDistinguisher{}, ErrInvalidRouteDistinguisher{RD: rd.String(), Reason: reason}
	}
	return RouteDistinguisher{Admin: typed.Admin, Index: typed.Assigned}, nil
}

// RouteTarget is a two-octet AS-specific route target: the only form the
// overlay derives and therefore the only form it imports.
type RouteTarget struct {
	AS    uint16
	Value uint32
}

// String returns the RT as "as:value", the form policy allowlists use.
func (rt RouteTarget) String() string {
	return strconv.FormatUint(uint64(rt.AS), 10) + ":" + strconv.FormatUint(uint64(rt.Value), 10)
}

// native returns the RT as a transitive extended community.
func (rt RouteTarget) native() gobgp.ExtendedCommunityInterface {
	return gobgp.NewTwoOctetAsSpecificExtended(gobgp.EC_SUBTYPE_ROUTE_TARGET, rt.AS, rt.Value, true)
}

// AutoRouteTarget derives the route target of a VNI (RFC 8365 §5.1.2.1):
// the overlay ASN as global administrator and, as local administrator,
// A=0 (automatic), Type=1 (VXLAN), the 4-bit D-ID and the 24-bit VNI.
// Every VTEP derives the same RT for the same VNI, so no RT is configured.
func AutoRouteTarget(asn uint16, domainID uint8, vni uint32) (RouteTarget, error) {
	if asn < MinOverlayASN || asn > MaxOverlayASN {
		return RouteTarget{}, ErrRouteTargetInvalid{
			RT:     strconv.FormatUint(uint64(asn), 10),
			Reason: "the overlay ASN must be a private 2-octet ASN (64512-65534)",
		}
	}
	if domainID > MaxDomainID {
		return RouteTarget{}, ErrRouteTargetInvalid{
			RT:     strconv.FormatUint(uint64(asn), 10),
			Reason: "the domain ID is a 4-bit field (0-15)",
		}
	}
	if err := validateVNI(vni); err != nil {
		return RouteTarget{}, err
	}
	return RouteTarget{
		AS:    asn,
		Value: autoRTTypeVXLAN<<28 | uint32(domainID)<<24 | vni,
	}, nil
}

// rdInstance names what an RD is allocated to: the MAC-VRF of an L2VNI or
// the IP-VRF of an L3VNI.
type rdInstance struct {
	ipVRF bool
	vni   uint32
}

// rdAllocator hands out the 16-bit RD numbers of one originator. A VNI is
// 24 bits and does not fit, so each EVI and IP-VRF gets the next free
// number, and a released number is reused. It is not safe for concurrent
// use; the EVPN manager holds its lock around every call.
type rdAllocator struct {
	admin    netip.Addr
	next     uint32
	free     []uint16
	assigned map[rdInstance]uint16
}

// newRDAllocator returns an allocator for the originator admin.
func newRDAllocator(admin netip.Addr) *rdAllocator {
	return &rdAllocator{admin: admin, next: 1, assigned: make(map[rdInstance]uint16)}
}

// allocate returns the RD of instance, assigning one on first use.
func (a *rdAllocator) allocate(instance rdInstance) (RouteDistinguisher, error) {
	if index, ok := a.assigned[instance]; ok {
		return RouteDistinguisher{Admin: a.admin, Index: index}, nil
	}
	var index uint16
	switch {
	case len(a.free) > 0:
		index = a.free[len(a.free)-1]
		a.free = a.free[:len(a.free)-1]
	case a.next <= 0xffff:
		index = uint16(a.next)
		a.next++
	default:
		return RouteDistinguisher{}, ErrRouteDistinguishersExhausted{Admin: a.admin}
	}
	a.assigned[instance] = index
	return RouteDistinguisher{Admin: a.admin, Index: index}, nil
}

// lookup returns the RD of instance, if it has one.
func (a *rdAllocator) lookup(instance rdInstance) (RouteDistinguisher, bool) {
	index, ok := a.assigned[instance]
	return RouteDistinguisher{Admin: a.admin, Index: index}, ok
}

// release returns the RD of instance to the pool.
func (a *rdAllocator) release(instance rdInstance) {
	index, ok := a.assigned[instance]
	if !ok {
		return
	}
	delete(a.assigned, instance)
	a.free = append(a.free, index)
}

// validateVNI checks a VNI is a non-zero 24-bit value.
func validateVNI(vni uint32) error {
	if vni < MinVNI || vni > MaxVNI {
		return ErrInvalidVNI{VNI: vni, Reason: "must be 1-16777215"}
	}
	return nil
}

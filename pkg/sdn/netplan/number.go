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
	"encoding/binary"
	"net/netip"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

const (
	// MinEnvironment is the lowest environment number. VLANs 1-199 are left
	// to the site network beside the platform.
	MinEnvironment uint16 = 2

	// MaxEnvironment is the highest environment number: block 40 holds VLANs
	// 4000-4094 (offsets 95-99 do not exist in it).
	MaxEnvironment uint16 = 40

	// BlockSize is the number of VLAN IDs in an environment block.
	BlockSize = 100

	// MaxVLAN is the highest IEEE 802.1Q VLAN ID.
	MaxVLAN = 4094

	// VNIBlock is the VNI span of one environment: overlay network n of
	// environment E is VNI E·VNIBlock+n.
	VNIBlock uint32 = 100000

	// MaxNetworksPerEnvironment is the number of overlay networks (VNIs) an
	// environment can hold.
	MaxNetworksPerEnvironment uint32 = VNIBlock - 1

	// MaxConntrackZones is the number of conntrack zones a host can hold. It
	// is shared by every environment on the host (staging VMs on prod hosts
	// share one budget).
	MaxConntrackZones = 65535

	// MTU is the MTU of every platform switch port and of the peer-link, so
	// VXLAN encapsulation never fragments.
	MTU = 9216
)

// Reference host numbering inside a zone subnet, as offsets from the
// network address.
const (
	// HostGateway is the gateway address: the VRRP address of a gateway pair
	// on a zone, or the distributed anycast gateway of an overlay.
	HostGateway uint32 = 1

	// HostGatewayNodeFirst and HostGatewayNodeLast bound the gateway nodes'
	// own addresses.
	HostGatewayNodeFirst uint32 = 2
	HostGatewayNodeLast  uint32 = 3

	// HostControlPlaneFirst and HostControlPlaneLast bound the
	// control-plane nodes.
	HostControlPlaneFirst uint32 = 10
	HostControlPlaneLast  uint32 = 19

	// HostStaticFirst and HostStaticLast bound the other statically
	// addressed hosts (compute and storage nodes).
	HostStaticFirst uint32 = 20
	HostStaticLast  uint32 = 49

	// HostDHCPFirst is the first address of a zone's DHCP range; the range
	// runs to the last usable address.
	HostDHCPFirst uint32 = 50
)

// DefaultBase is the reference IPv4 address base.
var DefaultBase = netip.MustParsePrefix("10.0.0.0/8")

// HostServices4 is the link-local address of the per-VRF host services
// (DNS, metadata). The same address answers in every VRF and is never
// allocatable.
var HostServices4 = netip.MustParseAddr("169.254.169.253")

// hostServicesSubnetID is the IPv6 subnet ID of the reserved per-VRF host
// services /64 inside the deployment ULA /48. VLAN-derived subnet IDs stop
// at 0x4094, so it never collides with a zone.
const hostServicesSubnetID uint16 = 0xffff

// ulaSpace is the RFC 4193 locally assigned ULA space (L=1).
var ulaSpace = netip.MustParsePrefix("fd00::/8")

// VLAN returns the VLAN ID of the zone at offset off in environment e:
// e·100+off.
func VLAN(e uint16, off zone.Offset) (uint16, error) {
	if off > zone.MaxOffset {
		return 0, ErrOffset{Offset: off}
	}
	v := uint32(e)*BlockSize + uint32(off)
	if v < 1 || v > MaxVLAN {
		return 0, ErrVLANOutOfRange{VLAN: v}
	}
	return uint16(v), nil
}

// Subnet4 returns the IPv4 subnet of the zone at offset off in environment
// e on the /8 base: <base>.e.off.0/24.
func Subnet4(base netip.Prefix, e uint16, off zone.Offset) (netip.Prefix, error) {
	if err := validateBase(base); err != nil {
		return netip.Prefix{}, err
	}
	if off > zone.MaxOffset {
		return netip.Prefix{}, ErrOffset{Offset: off}
	}
	if e < MinEnvironment || e > MaxEnvironment {
		return netip.Prefix{}, ErrEnvironmentID{ID: e}
	}
	a := base.Addr().As4()
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{a[0], byte(e), byte(off), 0}), 24), nil
}

// Subnet6 returns the IPv6 /64 of a VLAN inside the deployment ULA /48: the
// subnet ID is the VLAN's decimal digits read as hex, so VLAN 406 in
// fd12:3456:789a::/48 is fd12:3456:789a:406::/64.
func Subnet6(ula netip.Prefix, vlan uint16) (netip.Prefix, error) {
	if err := validateULA(ula); err != nil {
		return netip.Prefix{}, err
	}
	if vlan < 1 || vlan > MaxVLAN {
		return netip.Prefix{}, ErrVLANOutOfRange{VLAN: uint32(vlan)}
	}
	id, err := strconv.ParseUint(strconv.Itoa(int(vlan)), 16, 16)
	if err != nil {
		return netip.Prefix{}, ErrVLANOutOfRange{VLAN: uint32(vlan)}
	}
	return subnet6WithID(ula, uint16(id)), nil
}

// subnet6WithID returns the /64 with the given subnet ID inside a /48.
func subnet6WithID(ula netip.Prefix, id uint16) netip.Prefix {
	b := ula.Addr().As16()
	binary.BigEndian.PutUint16(b[6:8], id)
	for i := 8; i < 16; i++ {
		b[i] = 0
	}
	return netip.PrefixFrom(netip.AddrFrom16(b), 64)
}

// VNI returns the VNI of overlay network n in environment e: e·100000+n.
// Network numbers run 1-MaxNetworksPerEnvironment.
func VNI(e uint16, n uint32) (uint32, error) {
	if e < MinEnvironment || e > MaxEnvironment {
		return 0, ErrEnvironmentID{ID: e}
	}
	if n < 1 || n > MaxNetworksPerEnvironment {
		return 0, ErrVNIOutOfRange{Network: n}
	}
	return uint32(e)*VNIBlock + n, nil
}

// SplitVNI returns the environment and overlay network number a VNI
// encodes. ok is false when the VNI is not a valid netplan VNI.
func SplitVNI(vni uint32) (e uint16, n uint32, ok bool) {
	env := vni / VNIBlock
	n = vni % VNIBlock
	if env < uint32(MinEnvironment) || env > uint32(MaxEnvironment) || n == 0 {
		return 0, 0, false
	}
	return uint16(env), n, true
}

// Host returns the address host positions above the network address of p.
// It refuses the network address itself and, for prefixes shorter than
// /31, the broadcast address.
func Host(p netip.Prefix, host uint32) (netip.Addr, error) {
	p = p.Masked()
	size := prefixSize(p)
	if host == 0 || uint64(host) >= size || (p.Addr().Is4() && p.Bits() < 31 && uint64(host) == size-1) {
		return netip.Addr{}, ErrHostNumber{Prefix: p, Host: host}
	}
	return addAddr(p.Addr(), uint64(host)), nil
}

// Gateway returns the gateway (VRRP or anycast) address of a subnet: its
// first host address.
func Gateway(p netip.Prefix) (netip.Addr, error) {
	return Host(p, HostGateway)
}

// GatewayNode returns the address of gateway node i (0 or 1) in a subnet.
func GatewayNode(p netip.Prefix, i int) (netip.Addr, error) {
	return bandHost(p, HostGatewayNodeFirst, HostGatewayNodeLast, i)
}

// ControlPlaneNode returns the address of control-plane node i (0-9) in a
// subnet.
func ControlPlaneNode(p netip.Prefix, i int) (netip.Addr, error) {
	return bandHost(p, HostControlPlaneFirst, HostControlPlaneLast, i)
}

// StaticHost returns the address of static host i (0-29) in a subnet.
func StaticHost(p netip.Prefix, i int) (netip.Addr, error) {
	return bandHost(p, HostStaticFirst, HostStaticLast, i)
}

// bandHost returns host first+i of p when it stays inside [first, last].
func bandHost(p netip.Prefix, first, last uint32, i int) (netip.Addr, error) {
	if i < 0 || int64(i) > int64(last-first) {
		host := first
		if i > 0 && int64(i) <= int64(^uint32(0)-first) {
			host = first + uint32(i)
		}
		return netip.Addr{}, ErrHostNumber{Prefix: p.Masked(), Host: host}
	}
	return Host(p, first+uint32(i))
}

// validateBase checks that base is a masked IPv4 /8.
func validateBase(base netip.Prefix) error {
	if !base.IsValid() || !base.Addr().Is4() || base.Bits() != 8 || base.Masked() != base {
		return ErrBase{Base: base}
	}
	return nil
}

// validateULA checks that ula is a masked /48 inside fd00::/8.
func validateULA(ula netip.Prefix) error {
	if !ula.IsValid() || !ula.Addr().Is6() || ula.Addr().Is4In6() || ula.Bits() != 48 ||
		ula.Masked() != ula || !ulaSpace.Contains(ula.Addr()) {
		return ErrULA{ULA: ula}
	}
	return nil
}

// prefixSize returns the number of addresses in p (saturating at 2^64 for
// IPv6 prefixes shorter than /64).
func prefixSize(p netip.Prefix) uint64 {
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits >= 64 {
		return ^uint64(0)
	}
	return uint64(1) << hostBits
}

// lastAddr returns the last address of p: every host bit set.
func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	b := p.Addr().AsSlice()
	for bit := p.Bits(); bit < len(b)*8; bit++ {
		b[bit/8] |= 0x80 >> (bit % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// addAddr returns a advanced by n positions.
func addAddr(a netip.Addr, n uint64) netip.Addr {
	if a.Is4() {
		b := a.As4()
		v := uint64(binary.BigEndian.Uint32(b[:])) + n
		binary.BigEndian.PutUint32(b[:], uint32(v))
		return netip.AddrFrom4(b)
	}
	b := a.As16()
	lo := binary.BigEndian.Uint64(b[8:])
	hi := binary.BigEndian.Uint64(b[:8])
	sum := lo + n
	if sum < lo {
		hi++
	}
	binary.BigEndian.PutUint64(b[8:], sum)
	binary.BigEndian.PutUint64(b[:8], hi)
	return netip.AddrFrom16(b)
}

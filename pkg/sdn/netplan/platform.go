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
)

// PlatformHost returns the platform-VRF address of attested host n: host n
// of the RangePlatformHosts range (<base>.E.144.0/20), so 1 to 4094. A
// number outside that span is refused with ErrHostNumber.
func (p *Plan) PlatformHost(n uint32) (netip.Addr, error) {
	return Host(p.ranges[RangePlatformHosts], n)
}

// PlatformHostNumber is the reverse of PlatformHost: the host number of an
// address in the RangePlatformHosts range (<base>.E.144.0/20). It reports
// false for an address outside the range, for the range's network and
// broadcast addresses and for an IPv6 address.
func (p *Plan) PlatformHostNumber(a netip.Addr) (uint32, bool) {
	r, ok := p.ranges[RangePlatformHosts]
	if !ok || !a.Is4() || !r.Addr().Is4() || !r.Contains(a) {
		return 0, false
	}
	r = r.Masked()
	base, addr := r.Addr().As4(), a.As4()
	n := binary.BigEndian.Uint32(addr[:]) - binary.BigEndian.Uint32(base[:])
	broadcast := uint32(1)<<(32-r.Bits()) - 1
	if n == 0 || (r.Bits() < 31 && n == broadcast) {
		return 0, false
	}
	return n, true
}

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

package vpn

import (
	"net/netip"
)

// IP header offsets the plane reads. It parses nothing beyond the source
// and destination addresses: forwarding needs no more, and a parser that
// walks options is a parser that can be attacked.
const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
)

// packetAddresses returns the source and destination addresses of an IPv4
// or IPv6 packet. It reports false for a packet too short to carry them or
// of an unknown version, which the caller drops.
func packetAddresses(pkt []byte) (src, dst netip.Addr, ok bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < ipv4HeaderLen {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < ipv6HeaderLen {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40])), true
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}

// prefixRange returns the first and last address of a prefix, which is how
// RFC 9484 expresses a route (an inclusive address range, not a prefix).
func prefixRange(p netip.Prefix) (start, end netip.Addr) {
	p = p.Masked()
	start = p.Addr()
	if start.Is4() {
		a := start.As4()
		host := 32 - p.Bits()
		for i := 0; i < host; i++ {
			a[3-i/8] |= 1 << (i % 8)
		}
		return start, netip.AddrFrom4(a)
	}
	a := start.As16()
	host := 128 - p.Bits()
	for i := 0; i < host; i++ {
		a[15-i/8] |= 1 << (i % 8)
	}
	return start, netip.AddrFrom16(a)
}

// allowedSource reports whether a packet a client sent may be forwarded to
// the host: it must parse, and its source must be exactly the address the
// client's lease holds. A client may source traffic from nothing else.
func allowedSource(pkt []byte, leased netip.Addr) bool {
	src, _, ok := packetAddresses(pkt)
	return ok && src == leased
}

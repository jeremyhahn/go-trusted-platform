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

package fhrp

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// Protocol constants from RFC 5798.
const (
	// Version is the VRRP version this speaker implements.
	Version = 3
	// TypeAdvertisement is the only VRRPv3 message type.
	TypeAdvertisement = 1
	// ProtocolNumber is VRRP's IP protocol number.
	ProtocolNumber = 112
	// PriorityOwner marks the router that owns the virtual addresses.
	PriorityOwner = 255
	// PriorityDefault is the default backup priority (§5.2.4).
	PriorityDefault = 100
	// PriorityRelease is sent by a Master that is shutting down (§6.4.3).
	PriorityRelease = 0
	// DefaultAdvertIntervalCentiseconds is 1 s, the RFC default.
	DefaultAdvertIntervalCentiseconds = 100
	// MaxAdvertIntervalCentiseconds is the 12-bit field's ceiling (§5.2.7).
	MaxAdvertIntervalCentiseconds = 4095
	// RequiredTTL is the TTL / hop limit an advertisement must carry (§7.1).
	RequiredTTL = 255

	headerLen = 8
)

// Family selects IPv4 or IPv6 operation for a group.
type Family uint8

const (
	// FamilyIPv4 groups advertise to 224.0.0.18 with MAC 00-00-5E-00-01-{VRID}.
	FamilyIPv4 Family = iota + 1
	// FamilyIPv6 groups advertise to ff02::12 with MAC 00-00-5E-00-02-{VRID}.
	FamilyIPv6
)

// String implements fmt.Stringer.
func (f Family) String() string {
	switch f {
	case FamilyIPv4:
		return "ipv4"
	case FamilyIPv6:
		return "ipv6"
	default:
		return "unknown"
	}
}

// Multicast group addresses (§5.1.1.2 / §5.1.2.2).
var (
	MulticastIPv4 = netip.MustParseAddr("224.0.0.18")
	MulticastIPv6 = netip.MustParseAddr("ff02::12")
)

// MulticastAddr returns the advertisement destination for the family.
func (f Family) MulticastAddr() netip.Addr {
	if f == FamilyIPv6 {
		return MulticastIPv6
	}
	return MulticastIPv4
}

// VirtualMAC returns the IANA-assigned virtual router MAC for vrid (§7.3):
// 00-00-5E-00-01-{VRID} for IPv4 and 00-00-5E-00-02-{VRID} for IPv6.
func VirtualMAC(f Family, vrid uint8) net.HardwareAddr {
	typ := byte(0x01)
	if f == FamilyIPv6 {
		typ = 0x02
	}
	return net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, typ, vrid}
}

// Advertisement is a decoded VRRPv3 ADVERTISEMENT (§5.2).
type Advertisement struct {
	VRID uint8
	// Priority is the sender's priority; 0 announces a release.
	Priority uint8
	// MaxAdvertInterval is the sender's Master_Adver_Interval in
	// centiseconds (12 bits).
	MaxAdvertInterval uint16
	// Addresses are the virtual addresses, all of one family.
	Addresses []netip.Addr
}

// Family reports the address family of the advertisement, FamilyIPv4 when
// it carries no address.
func (a *Advertisement) Family() Family {
	if len(a.Addresses) > 0 && a.Addresses[0].Is6() {
		return FamilyIPv6
	}
	return FamilyIPv4
}

// Marshal encodes the advertisement with the checksum computed over the
// message and the pseudo-header for src → dst (§5.2.8: the pseudo-header of
// RFC 2460 §8.1 with next header 112, for both families).
func (a *Advertisement) Marshal(src, dst netip.Addr) ([]byte, error) {
	if a.MaxAdvertInterval == 0 || a.MaxAdvertInterval > MaxAdvertIntervalCentiseconds {
		return nil, &ErrInvalidPacket{Reason: "max advertisement interval out of range"}
	}
	if len(a.Addresses) == 0 || len(a.Addresses) > 255 {
		return nil, &ErrInvalidPacket{Reason: "address count out of range"}
	}
	fam := a.Family()
	addrLen := 4
	if fam == FamilyIPv6 {
		addrLen = 16
	}
	for _, addr := range a.Addresses {
		if (fam == FamilyIPv6) != addr.Is6() {
			return nil, &ErrInvalidPacket{Reason: "mixed address families"}
		}
	}
	if (fam == FamilyIPv6) != src.Is6() || (fam == FamilyIPv6) != dst.Is6() {
		return nil, &ErrInvalidPacket{Reason: "pseudo-header family does not match the addresses"}
	}
	buf := make([]byte, headerLen+addrLen*len(a.Addresses))
	buf[0] = Version<<4 | TypeAdvertisement
	buf[1] = a.VRID
	buf[2] = a.Priority
	buf[3] = uint8(len(a.Addresses))
	binary.BigEndian.PutUint16(buf[4:6], a.MaxAdvertInterval&0x0fff)
	off := headerLen
	for _, addr := range a.Addresses {
		raw := addr.AsSlice()
		copy(buf[off:off+addrLen], raw)
		off += addrLen
	}
	binary.BigEndian.PutUint16(buf[6:8], checksum(buf, src, dst))
	return buf, nil
}

// Unmarshal decodes and verifies an advertisement received from src to dst
// (§7.1: version 3, type 1, checksum, at least one address of the
// destination's family). The TTL check is the transport's, because only it
// sees the IP header.
func Unmarshal(buf []byte, src, dst netip.Addr) (*Advertisement, error) {
	if len(buf) < headerLen {
		return nil, &ErrInvalidPacket{Reason: "shorter than the header"}
	}
	if buf[0]>>4 != Version {
		return nil, &ErrInvalidPacket{Reason: "not version 3"}
	}
	if buf[0]&0x0f != TypeAdvertisement {
		return nil, &ErrInvalidPacket{Reason: "not an advertisement"}
	}
	count := int(buf[3])
	if count == 0 {
		return nil, &ErrInvalidPacket{Reason: "no addresses"}
	}
	addrLen := 4
	if dst.Is6() {
		addrLen = 16
	}
	if len(buf) != headerLen+count*addrLen {
		return nil, &ErrInvalidPacket{Reason: "length does not match the address count"}
	}
	if checksum(buf, src, dst) != 0 {
		return nil, &ErrInvalidPacket{Reason: "checksum mismatch"}
	}
	adv := &Advertisement{
		VRID:              buf[1],
		Priority:          buf[2],
		MaxAdvertInterval: binary.BigEndian.Uint16(buf[4:6]) & 0x0fff,
		Addresses:         make([]netip.Addr, 0, count),
	}
	if adv.MaxAdvertInterval == 0 {
		return nil, &ErrInvalidPacket{Reason: "zero advertisement interval"}
	}
	for i := 0; i < count; i++ {
		off := headerLen + i*addrLen
		addr, ok := netip.AddrFromSlice(buf[off : off+addrLen])
		if !ok {
			return nil, &ErrInvalidPacket{Reason: "malformed address"}
		}
		adv.Addresses = append(adv.Addresses, addr)
	}
	return adv, nil
}

// checksum returns the one's-complement checksum of msg preceded by the
// pseudo-header for src → dst. Computing it over a message whose checksum
// field is already set yields 0 for a valid message.
func checksum(msg []byte, src, dst netip.Addr) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src.AsSlice())
	add(dst.AsSlice())
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(msg)))
	if src.Is6() {
		// RFC 2460 §8.1: 32-bit upper-layer length, 3 zero bytes, next header.
		add(length)
		add([]byte{0, 0, 0, ProtocolNumber})
	} else {
		// The IPv4 pseudo-header (RFC 768 shape): zero, protocol, 16-bit length.
		add([]byte{0, ProtocolNumber})
		add(length[2:])
	}
	add(msg)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

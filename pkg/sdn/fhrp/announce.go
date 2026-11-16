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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"
)

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// gratuitousARPFrame builds the Ethernet frame of a gratuitous ARP reply
// for addr from hw to the broadcast address: sender and target protocol
// address both addr, so every neighbour cache on the segment moves to hw.
func gratuitousARPFrame(hw net.HardwareAddr, addr netip.Addr) ([]byte, error) {
	if !addr.Is4() {
		return nil, &ErrInvalidPacket{Reason: "gratuitous ARP needs an IPv4 address"}
	}
	pkt := &arp.Packet{
		Operation:          arp.OperationReply,
		SenderHardwareAddr: hw,
		SenderProtocolAddr: addr.AsSlice(),
		TargetHardwareAddr: broadcastMAC,
		TargetProtocolAddr: addr.AsSlice(),
	}
	return pkt.MarshalFrame(hw, broadcastMAC)
}

// neighborAdvertisementBody builds the ICMPv6 body of an unsolicited
// neighbour advertisement (RFC 4861 §4.4): flags R=1 S=0 O=1, the target
// address, and a target link-layer address option carrying hw.
func neighborAdvertisementBody(addr netip.Addr, hw net.HardwareAddr) []byte {
	body := make([]byte, 4+16+8)
	// Router=1, Solicited=0, Override=1: the virtual address is a
	// router, and a clear R flag would drop it from a client's Default
	// Router List (RFC 4861 section 7.2.5).
	binary.BigEndian.PutUint32(body[0:4], 0xA0000000)
	copy(body[4:20], addr.AsSlice())
	body[20], body[21] = 2, 1
	copy(body[22:28], hw)
	return body
}

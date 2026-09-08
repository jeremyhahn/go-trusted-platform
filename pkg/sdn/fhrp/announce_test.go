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
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"
)

func TestGratuitousARPFrame(t *testing.T) {
	hw := net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x01, 0x14}
	frame, err := gratuitousARPFrame(hw, netip.MustParseAddr("198.18.0.1"))
	require.NoError(t, err)
	// Ethernet: broadcast destination, our source, ARP EtherType.
	assert.Equal(t, broadcastMAC, net.HardwareAddr(frame[0:6]))
	assert.Equal(t, hw, net.HardwareAddr(frame[6:12]))
	assert.Equal(t, []byte{0x08, 0x06}, frame[12:14])
	pkt, err := arp.UnmarshalFrame(frame)
	require.NoError(t, err)
	assert.Equal(t, uint16(arp.OperationReply), pkt.Operation)
	assert.Equal(t, hw, pkt.SenderHardwareAddr)
	assert.True(t, pkt.SenderProtocolAddr.Equal(net.IPv4(172, 16, 200, 1)))
	assert.True(t, pkt.TargetProtocolAddr.Equal(net.IPv4(172, 16, 200, 1)))

	_, err = gratuitousARPFrame(hw, netip.MustParseAddr("2602:f5bb::1"))
	require.Error(t, err)
}

func TestNeighborAdvertisementBody(t *testing.T) {
	hw := net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x02, 0x14}
	body := neighborAdvertisementBody(netip.MustParseAddr("2602:f5bb::1"), hw)
	require.Len(t, body, 28)
	assert.Equal(t, []byte{0x20, 0, 0, 0}, body[0:4], "Override set, Router and Solicited clear")
	assert.Equal(t, netip.MustParseAddr("2602:f5bb::1").AsSlice(), body[4:20])
	assert.Equal(t, byte(2), body[20], "target link-layer address option")
	assert.Equal(t, byte(1), body[21], "one 8-byte unit")
	assert.Equal(t, hw, net.HardwareAddr(body[22:28]))
}

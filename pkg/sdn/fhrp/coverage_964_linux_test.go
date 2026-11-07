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

//go:build linux

package fhrp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

// udpRawConn wraps a loopback UDP socket in the raw transport's conn, so the
// IPv4 send / receive paths run without a raw socket.
func udpRawConn(t *testing.T) (*rawConn, net.PacketConn) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	p := ipv4.NewPacketConn(pc)
	require.NoError(t, p.SetControlMessage(ipv4.FlagTTL, true))
	return &rawConn{pc: pc, v4: p, src: net.IPv4(127, 0, 0, 1)}, pc
}

func TestRawConn_ReceiveReportsPayloadAndTTL(t *testing.T) {
	c, pc := udpRawConn(t)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })
	require.NoError(t, ipv4.NewPacketConn(peer).SetTTL(RequiredTTL))
	_, err = peer.WriteTo([]byte("vrrp"), pc.LocalAddr())
	require.NoError(t, err)

	payload, _, ttl, err := c.Receive(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []byte("vrrp"), payload)
	assert.Equal(t, RequiredTTL, ttl)
}

func TestRawConn_ReceiveHonoursTheContextDeadline(t *testing.T) {
	c, _ := udpRawConn(t)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	_, _, _, err := c.Receive(ctx)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestRawConn_FailsOnceClosed(t *testing.T) {
	c, _ := udpRawConn(t)
	require.NoError(t, c.Close())

	_, _, _, err := c.Receive(context.Background())
	require.True(t, errors.Is(err, net.ErrClosed), "receive: %v", err)
	require.Error(t, c.Send([]byte("vrrp"), netip.MustParseAddr("127.0.0.1")))
}

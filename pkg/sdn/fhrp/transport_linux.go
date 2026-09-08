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
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// NewRawTransport returns the production Transport: a raw IP socket for
// protocol 112 bound to the interface and joined to the family's VRRP
// multicast group, sending with TTL / hop limit 255 and reporting the TTL
// each packet arrived with. It needs CAP_NET_RAW.
func NewRawTransport() Transport { return rawTransport{} }

type rawTransport struct{}

// Open implements Transport.
func (rawTransport) Open(iface string, family Family, source netip.Addr) (Conn, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	network := "ip4:112"
	if family == FamilyIPv6 {
		network = "ip6:112"
	}
	pc, err := net.ListenPacket(network, source.String())
	if err != nil {
		return nil, err
	}
	group := family.MulticastAddr()
	c := &rawConn{pc: pc}
	if family == FamilyIPv6 {
		p := ipv6.NewPacketConn(pc)
		if err := p.JoinGroup(ifi, &net.UDPAddr{IP: group.AsSlice()}); err != nil {
			_ = pc.Close()
			return nil, err
		}
		if err := p.SetHopLimit(RequiredTTL); err != nil {
			_ = pc.Close()
			return nil, err
		}
		if err := p.SetMulticastHopLimit(RequiredTTL); err != nil {
			_ = pc.Close()
			return nil, err
		}
		if err := p.SetMulticastInterface(ifi); err != nil {
			_ = pc.Close()
			return nil, err
		}
		if err := p.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
			_ = pc.Close()
			return nil, err
		}
		c.v6 = p
		return c, nil
	}
	p := ipv4.NewPacketConn(pc)
	if err := p.JoinGroup(ifi, &net.UDPAddr{IP: group.AsSlice()}); err != nil {
		_ = pc.Close()
		return nil, err
	}
	if err := p.SetTTL(RequiredTTL); err != nil {
		_ = pc.Close()
		return nil, err
	}
	if err := p.SetMulticastTTL(RequiredTTL); err != nil {
		_ = pc.Close()
		return nil, err
	}
	if err := p.SetMulticastInterface(ifi); err != nil {
		_ = pc.Close()
		return nil, err
	}
	if err := p.SetControlMessage(ipv4.FlagTTL, true); err != nil {
		_ = pc.Close()
		return nil, err
	}
	c.v4 = p
	return c, nil
}

type rawConn struct {
	pc net.PacketConn
	v4 *ipv4.PacketConn
	v6 *ipv6.PacketConn
}

// Send implements Conn.
func (c *rawConn) Send(payload []byte, dst netip.Addr) error {
	addr := &net.IPAddr{IP: dst.AsSlice()}
	if c.v6 != nil {
		_, err := c.v6.WriteTo(payload, nil, addr)
		return err
	}
	_, err := c.v4.WriteTo(payload, nil, addr)
	return err
}

// Receive implements Conn. The context's deadline, when set, bounds the
// read; cancellation is honoured by Close.
func (c *rawConn) Receive(ctx context.Context) ([]byte, netip.Addr, int, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.pc.SetReadDeadline(deadline)
	} else {
		_ = c.pc.SetReadDeadline(time.Time{})
	}
	buf := make([]byte, 1500)
	if c.v6 != nil {
		n, cm, from, err := c.v6.ReadFrom(buf)
		if err != nil {
			return nil, netip.Addr{}, 0, err
		}
		ttl := 0
		if cm != nil {
			ttl = cm.HopLimit
		}
		return buf[:n], addrOf(from), ttl, nil
	}
	n, cm, from, err := c.v4.ReadFrom(buf)
	if err != nil {
		return nil, netip.Addr{}, 0, err
	}
	ttl := 0
	if cm != nil {
		ttl = cm.TTL
	}
	return buf[:n], addrOf(from), ttl, nil
}

// Close implements Conn.
func (c *rawConn) Close() error { return c.pc.Close() }

func addrOf(a net.Addr) netip.Addr {
	if ipa, ok := a.(*net.IPAddr); ok {
		if addr, ok := netip.AddrFromSlice(ipa.IP); ok {
			return addr.Unmap()
		}
	}
	return netip.Addr{}
}

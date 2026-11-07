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
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// NewRawTransport returns the production Transport: a raw IP socket for
// protocol 112 bound to the interface (SO_BINDTODEVICE) and joined to the
// family's VRRP multicast group, sending with TTL / hop limit 255 from the
// group's source address and reporting the TTL each packet arrived with. It
// needs CAP_NET_RAW.
//
// The IPv4 socket is not bound to the source address: Linux delivers an
// IPv4 packet to a raw socket only when the socket's bound address equals
// the packet's destination (raw_v4_match), so a socket bound to the source
// never receives an advertisement sent to 224.0.0.18 (RFC 9568 §5.1.1.2).
// The source travels with each send instead (IP_PKTINFO). IPv6 raw sockets
// also match a joined multicast group, so the IPv6 socket keeps its bind.
func NewRawTransport() Transport { return rawTransport{} }

type rawTransport struct{}

// ipv4Conn is the part of *ipv4.PacketConn the transport uses; unit tests
// substitute a fake through newIPv4Conn.
type ipv4Conn interface {
	JoinGroup(ifi *net.Interface, group net.Addr) error
	SetTTL(ttl int) error
	SetMulticastTTL(ttl int) error
	SetMulticastInterface(ifi *net.Interface) error
	SetMulticastLoopback(on bool) error
	SetControlMessage(cf ipv4.ControlFlags, on bool) error
	WriteTo(b []byte, cm *ipv4.ControlMessage, dst net.Addr) (int, error)
	ReadFrom(b []byte) (int, *ipv4.ControlMessage, net.Addr, error)
}

// ipv6Conn is the part of *ipv6.PacketConn the transport and the
// unsolicited Neighbor Advertisement use; unit tests substitute a fake.
type ipv6Conn interface {
	JoinGroup(ifi *net.Interface, group net.Addr) error
	SetHopLimit(hoplim int) error
	SetMulticastHopLimit(hoplim int) error
	SetMulticastInterface(ifi *net.Interface) error
	SetControlMessage(cf ipv6.ControlFlags, on bool) error
	WriteTo(b []byte, cm *ipv6.ControlMessage, dst net.Addr) (int, error)
	ReadFrom(b []byte) (int, *ipv6.ControlMessage, net.Addr, error)
}

// Host seams: each defaults to the real host call and only unit tests
// replace them, so the raw-socket paths run without CAP_NET_RAW.
var (
	interfaceByName = net.InterfaceByName
	listenPacket    = func(lc *net.ListenConfig, network, address string) (net.PacketConn, error) {
		return lc.ListenPacket(context.Background(), network, address)
	}
	newIPv4Conn = func(pc net.PacketConn) ipv4Conn { return ipv4.NewPacketConn(pc) }
	newIPv6Conn = func(pc net.PacketConn) ipv6Conn { return ipv6.NewPacketConn(pc) }
)

// Open implements Transport.
func (rawTransport) Open(iface string, family Family, source netip.Addr) (Conn, error) {
	ifi, err := interfaceByName(iface)
	if err != nil {
		return nil, err
	}
	network, laddr := "ip4:112", "0.0.0.0"
	if family == FamilyIPv6 {
		network, laddr = "ip6:112", source.String()
	}
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		return bindToDevice(rc, iface)
	}}
	pc, err := listenPacket(&lc, network, laddr)
	if err != nil {
		return nil, err
	}
	group := family.MulticastAddr()
	c := &rawConn{pc: pc, src: source.AsSlice()}
	if family == FamilyIPv6 {
		p := newIPv6Conn(pc)
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
	p := newIPv4Conn(pc)
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
	// The unbound socket would hear its own advertisements looped back
	// and count each one in Health.Dropped.
	if err := p.SetMulticastLoopback(false); err != nil {
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

// bindToDevice scopes the socket to one interface (SO_BINDTODEVICE): it
// receives only what arrives there, as the unbound IPv4 socket would
// otherwise also see the groups of every other interface.
func bindToDevice(rc syscall.RawConn, iface string) error {
	var sockErr error
	if err := rc.Control(func(fd uintptr) {
		sockErr = unix.BindToDevice(int(fd), iface)
	}); err != nil {
		return err
	}
	return sockErr
}

type rawConn struct {
	pc net.PacketConn
	v4 ipv4Conn
	v6 ipv6Conn
	// src is the advertisement source; the unbound IPv4 socket sends it
	// as IP_PKTINFO's ipi_spec_dst.
	src net.IP
}

// Send implements Conn.
func (c *rawConn) Send(payload []byte, dst netip.Addr) error {
	addr := &net.IPAddr{IP: dst.AsSlice()}
	if c.v6 != nil {
		_, err := c.v6.WriteTo(payload, nil, addr)
		return err
	}
	_, err := c.v4.WriteTo(payload, &ipv4.ControlMessage{Src: c.src}, addr)
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

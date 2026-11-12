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
	"io"
	"net"
	"net/netip"

	"github.com/mdlayher/packet"
	vnl "github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// NewNetlinkProgrammer returns the production Programmer: virtual addresses
// are added to and removed from the interface over netlink, and a takeover
// is announced with a gratuitous ARP reply (IPv4) or an unsolicited
// neighbour advertisement (IPv6) whose link-layer address is the virtual
// router MAC (RFC 5798 §7.3). Placing the virtual MAC on a dedicated
// macvlan device is a follow-up; until then the interface's own MAC
// answers ARP for the addresses and the announcement teaches the segment
// that MAC.
func NewNetlinkProgrammer(opts ...ProgrammerOption) Programmer {
	p := &netlinkProgrammer{}
	for _, o := range opts {
		o(p)
	}
	return p
}

// ProgrammerOption configures the netlink programmer.
type ProgrammerOption func(*netlinkProgrammer)

// WithNetlinkHandle programs addresses through h — a handle bound to a
// network namespace (netlink.NewHandleAt) — instead of the process default.
func WithNetlinkHandle(h *vnl.Handle) ProgrammerOption {
	return func(p *netlinkProgrammer) { p.handle = h }
}

type netlinkProgrammer struct {
	handle *vnl.Handle
}

// frameWriter is the part of *packet.Conn the gratuitous ARP uses; unit
// tests substitute a fake through listenARP.
type frameWriter interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
	Close() error
}

// Host seams for the netlink and raw-socket calls made without a handle.
// Each defaults to the real host call and only unit tests replace them.
var (
	netlinkLinkByName  = vnl.LinkByName
	netlinkAddrReplace = vnl.AddrReplace
	netlinkAddrDel     = vnl.AddrDel
	netlinkAddrList    = vnl.AddrList
	listenARP          = func(ifi *net.Interface) (frameWriter, error) {
		conn, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ARP, nil)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	listenICMPv6 = func() (io.Closer, ipv6Conn, error) {
		pc, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			return nil, nil, err
		}
		return pc, pc.IPv6PacketConn(), nil
	}
)

func (p *netlinkProgrammer) linkByName(name string) (vnl.Link, error) {
	if p.handle != nil {
		return p.handle.LinkByName(name)
	}
	return netlinkLinkByName(name)
}

// AddAddress implements Programmer.
func (p *netlinkProgrammer) AddAddress(iface string, prefix netip.Prefix, _ net.HardwareAddr) error {
	link, err := p.linkByName(iface)
	if err != nil {
		return err
	}
	addr, err := vnl.ParseAddr(prefix.String())
	if err != nil {
		return err
	}
	if p.handle != nil {
		return p.handle.AddrReplace(link, addr)
	}
	return netlinkAddrReplace(link, addr)
}

// DeleteAddress implements Programmer.
func (p *netlinkProgrammer) DeleteAddress(iface string, prefix netip.Prefix, _ net.HardwareAddr) error {
	link, err := p.linkByName(iface)
	if err != nil {
		return err
	}
	addr, err := vnl.ParseAddr(prefix.String())
	if err != nil {
		return err
	}
	if p.handle != nil {
		err = p.handle.AddrDel(link, addr)
	} else {
		err = netlinkAddrDel(link, addr)
	}
	if err != nil && err.Error() == unix.EADDRNOTAVAIL.Error() {
		return nil
	}
	return err
}

// HasAddress implements AddressReader: true when iface holds an address
// with prefix's IP and prefix length.
func (p *netlinkProgrammer) HasAddress(iface string, prefix netip.Prefix) (bool, error) {
	link, err := p.linkByName(iface)
	if err != nil {
		return false, err
	}
	family := vnl.FAMILY_V6
	if prefix.Addr().Is4() {
		family = vnl.FAMILY_V4
	}
	var addrs []vnl.Addr
	if p.handle != nil {
		addrs, err = p.handle.AddrList(link, family)
	} else {
		addrs, err = netlinkAddrList(link, family)
	}
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		ones, _ := a.Mask.Size()
		if ip.Unmap() == prefix.Addr() && ones == prefix.Bits() {
			return true, nil
		}
	}
	return false, nil
}

// Announce implements Programmer. The raw sockets it opens live in the
// calling thread's network namespace.
func (p *netlinkProgrammer) Announce(iface string, addr netip.Addr, _ net.HardwareAddr) error {
	ifi, err := interfaceByName(iface)
	if err != nil {
		return err
	}
	if addr.Is6() {
		return announceNA(ifi, addr)
	}
	return announceARP(ifi, addr)
}

// announceARP sends a gratuitous ARP reply for addr from the interface's
// MAC to the broadcast address.
func announceARP(ifi *net.Interface, addr netip.Addr) error {
	conn, err := listenARP(ifi)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	frame, err := gratuitousARPFrame(ifi.HardwareAddr, addr)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(frame, &packet.Addr{HardwareAddr: broadcastMAC})
	return err
}

// announceNA sends an unsolicited neighbour advertisement (RFC 4861 §7.2.6)
// for addr to all-nodes with the Override flag and the interface's MAC as
// the target link-layer address.
func announceNA(ifi *net.Interface, addr netip.Addr) error {
	pc, p, err := listenICMPv6()
	if err != nil {
		return err
	}
	defer func() { _ = pc.Close() }()
	if err := p.SetHopLimit(RequiredTTL); err != nil {
		return err
	}
	if err := p.SetMulticastHopLimit(RequiredTTL); err != nil {
		return err
	}
	if err := p.SetMulticastInterface(ifi); err != nil {
		return err
	}
	msg := icmp.Message{Type: ipv6.ICMPTypeNeighborAdvertisement, Code: 0, Body: &icmp.RawBody{Data: neighborAdvertisementBody(addr, ifi.HardwareAddr)}}
	dst := net.ParseIP("ff02::1")
	// The ICMPv6 checksum is computed by the kernel for raw ICMPv6 sockets;
	// Marshal with a nil pseudo-header leaves it zero.
	wire, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = p.WriteTo(wire, &ipv6.ControlMessage{HopLimit: RequiredTTL, IfIndex: ifi.Index}, &net.IPAddr{IP: dst, Zone: ifi.Name})
	return err
}

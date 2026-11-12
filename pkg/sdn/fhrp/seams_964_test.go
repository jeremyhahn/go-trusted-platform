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
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//go:build linux

package fhrp

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/packet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// The tests in this file replace the package's host seams, so none of
// them calls t.Parallel.

// errSeam is the typed failure a fake returns from the step it is told
// to fail.
type errSeam struct{ step string }

func (e *errSeam) Error() string { return "injected failure at " + e.step }

// requireSeamErr asserts err is the errSeam a fake returned at step.
func requireSeamErr(t *testing.T, err error, step string) {
	t.Helper()
	var se *errSeam
	require.ErrorAs(t, err, &se)
	assert.Equal(t, step, se.step)
}

// failAt returns an errSeam when step is the one a fake must fail.
func failAt(want, step string) error {
	if want == step {
		return &errSeam{step: step}
	}
	return nil
}

// fakePacketConn stands in for the raw socket a seam would open.
type fakePacketConn struct {
	closed       int
	readDeadline time.Time
}

func (f *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, &errSeam{step: "ReadFrom"}
}
func (f *fakePacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, &errSeam{step: "WriteTo"}
}
func (f *fakePacketConn) Close() error                     { f.closed++; return nil }
func (f *fakePacketConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }
func (f *fakePacketConn) SetReadDeadline(d time.Time) error {
	f.readDeadline = d
	return nil
}

// fakeIPv4 records the socket options the transport sets and the
// datagrams it writes.
type fakeIPv4 struct {
	fail     string
	group    net.Addr
	ifi      *net.Interface
	ttl      int
	mttl     int
	loopback bool
	cf       ipv4.ControlFlags
	payload  []byte
	cm       *ipv4.ControlMessage
	dst      net.Addr
	read     []byte
	readCM   *ipv4.ControlMessage
	readFrom net.Addr
}

func (f *fakeIPv4) JoinGroup(_ *net.Interface, group net.Addr) error {
	f.group = group
	return failAt(f.fail, "JoinGroup")
}
func (f *fakeIPv4) SetTTL(ttl int) error { f.ttl = ttl; return failAt(f.fail, "SetTTL") }
func (f *fakeIPv4) SetMulticastTTL(ttl int) error {
	f.mttl = ttl
	return failAt(f.fail, "SetMulticastTTL")
}
func (f *fakeIPv4) SetMulticastInterface(ifi *net.Interface) error {
	f.ifi = ifi
	return failAt(f.fail, "SetMulticastInterface")
}
func (f *fakeIPv4) SetMulticastLoopback(on bool) error {
	f.loopback = on
	return failAt(f.fail, "SetMulticastLoopback")
}
func (f *fakeIPv4) SetControlMessage(cf ipv4.ControlFlags, on bool) error {
	if on {
		f.cf = cf
	}
	return failAt(f.fail, "SetControlMessage")
}
func (f *fakeIPv4) WriteTo(b []byte, cm *ipv4.ControlMessage, dst net.Addr) (int, error) {
	f.payload, f.cm, f.dst = append([]byte(nil), b...), cm, dst
	return len(b), failAt(f.fail, "WriteTo")
}
func (f *fakeIPv4) ReadFrom(b []byte) (int, *ipv4.ControlMessage, net.Addr, error) {
	if err := failAt(f.fail, "ReadFrom"); err != nil {
		return 0, nil, nil, err
	}
	return copy(b, f.read), f.readCM, f.readFrom, nil
}

// fakeIPv6 is the IPv6 twin of fakeIPv4; the transport and the
// unsolicited Neighbor Advertisement both use it.
type fakeIPv6 struct {
	fail     string
	group    net.Addr
	ifi      *net.Interface
	hop      int
	mhop     int
	cf       ipv6.ControlFlags
	payload  []byte
	cm       *ipv6.ControlMessage
	dst      net.Addr
	read     []byte
	readCM   *ipv6.ControlMessage
	readFrom net.Addr
}

func (f *fakeIPv6) JoinGroup(_ *net.Interface, group net.Addr) error {
	f.group = group
	return failAt(f.fail, "JoinGroup")
}
func (f *fakeIPv6) SetHopLimit(h int) error { f.hop = h; return failAt(f.fail, "SetHopLimit") }
func (f *fakeIPv6) SetMulticastHopLimit(h int) error {
	f.mhop = h
	return failAt(f.fail, "SetMulticastHopLimit")
}
func (f *fakeIPv6) SetMulticastInterface(ifi *net.Interface) error {
	f.ifi = ifi
	return failAt(f.fail, "SetMulticastInterface")
}
func (f *fakeIPv6) SetControlMessage(cf ipv6.ControlFlags, on bool) error {
	if on {
		f.cf = cf
	}
	return failAt(f.fail, "SetControlMessage")
}
func (f *fakeIPv6) WriteTo(b []byte, cm *ipv6.ControlMessage, dst net.Addr) (int, error) {
	f.payload, f.cm, f.dst = append([]byte(nil), b...), cm, dst
	return len(b), failAt(f.fail, "WriteTo")
}
func (f *fakeIPv6) ReadFrom(b []byte) (int, *ipv6.ControlMessage, net.Addr, error) {
	if err := failAt(f.fail, "ReadFrom"); err != nil {
		return 0, nil, nil, err
	}
	return copy(b, f.read), f.readCM, f.readFrom, nil
}

var seamIface = &net.Interface{
	Index:        7,
	Name:         "vrrp0",
	HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x5e, 0x00, 0x01, 0x0a},
}

// stubInterface makes interfaceByName return seamIface for its name.
func stubInterface(t *testing.T) {
	t.Helper()
	orig := interfaceByName
	t.Cleanup(func() { interfaceByName = orig })
	interfaceByName = func(name string) (*net.Interface, error) {
		if name != seamIface.Name {
			return nil, &errSeam{step: "InterfaceByName"}
		}
		return seamIface, nil
	}
}

// listenCall is what the listenPacket seam was asked to open.
type listenCall struct {
	network, address string
	control          bool
}

// stubTransport routes rawTransport.Open's socket calls to fakes.
func stubTransport(t *testing.T, pc *fakePacketConn, v4 *fakeIPv4, v6 *fakeIPv6) *listenCall {
	t.Helper()
	stubInterface(t)
	origListen, origV4, origV6 := listenPacket, newIPv4Conn, newIPv6Conn
	t.Cleanup(func() { listenPacket, newIPv4Conn, newIPv6Conn = origListen, origV4, origV6 })
	call := &listenCall{}
	listenPacket = func(lc *net.ListenConfig, network, address string) (net.PacketConn, error) {
		call.network, call.address, call.control = network, address, lc.Control != nil
		if pc == nil {
			return nil, &errSeam{step: "ListenPacket"}
		}
		return pc, nil
	}
	newIPv4Conn = func(net.PacketConn) ipv4Conn { return v4 }
	newIPv6Conn = func(net.PacketConn) ipv6Conn { return v6 }
	return call
}

func TestRawTransport_OpenIPv4SetsTheRFC9568SocketOptions(t *testing.T) {
	pc, v4 := &fakePacketConn{}, &fakeIPv4{}
	call := stubTransport(t, pc, v4, nil)
	src := netip.MustParseAddr("192.0.2.2")

	conn, err := rawTransport{}.Open(seamIface.Name, FamilyIPv4, src)
	require.NoError(t, err)

	assert.Equal(t, listenCall{network: "ip4:112", address: "0.0.0.0", control: true}, *call)
	rc, ok := conn.(*rawConn)
	require.True(t, ok)
	assert.Same(t, v4, rc.v4)
	assert.Nil(t, rc.v6)
	assert.Equal(t, net.IP(src.AsSlice()), rc.src)
	assert.Equal(t, &net.UDPAddr{IP: net.IP{224, 0, 0, 18}}, v4.group)
	assert.Equal(t, RequiredTTL, v4.ttl)
	assert.Equal(t, RequiredTTL, v4.mttl)
	assert.Same(t, seamIface, v4.ifi)
	assert.False(t, v4.loopback)
	assert.Equal(t, ipv4.FlagTTL, v4.cf)
	assert.Zero(t, pc.closed)
}

func TestRawTransport_OpenIPv4ClosesTheSocketOnEachFailure(t *testing.T) {
	steps := []string{"JoinGroup", "SetTTL", "SetMulticastTTL", "SetMulticastInterface", "SetMulticastLoopback", "SetControlMessage"}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			pc := &fakePacketConn{}
			stubTransport(t, pc, &fakeIPv4{fail: step}, nil)

			conn, err := rawTransport{}.Open(seamIface.Name, FamilyIPv4, netip.MustParseAddr("192.0.2.2"))
			requireSeamErr(t, err, step)
			assert.Nil(t, conn)
			assert.Equal(t, 1, pc.closed)
		})
	}
}

func TestRawTransport_OpenIPv6SetsTheRFC9568SocketOptions(t *testing.T) {
	pc, v6 := &fakePacketConn{}, &fakeIPv6{}
	call := stubTransport(t, pc, nil, v6)
	src := netip.MustParseAddr("fe80::2")

	conn, err := rawTransport{}.Open(seamIface.Name, FamilyIPv6, src)
	require.NoError(t, err)

	assert.Equal(t, listenCall{network: "ip6:112", address: "fe80::2", control: true}, *call)
	rc, ok := conn.(*rawConn)
	require.True(t, ok)
	assert.Same(t, v6, rc.v6)
	assert.Nil(t, rc.v4)
	assert.Equal(t, &net.UDPAddr{IP: net.ParseIP("ff02::12")}, v6.group)
	assert.Equal(t, RequiredTTL, v6.hop)
	assert.Equal(t, RequiredTTL, v6.mhop)
	assert.Same(t, seamIface, v6.ifi)
	assert.Equal(t, ipv6.FlagHopLimit, v6.cf)
	assert.Zero(t, pc.closed)
}

func TestRawTransport_OpenIPv6ClosesTheSocketOnEachFailure(t *testing.T) {
	steps := []string{"JoinGroup", "SetHopLimit", "SetMulticastHopLimit", "SetMulticastInterface", "SetControlMessage"}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			pc := &fakePacketConn{}
			stubTransport(t, pc, nil, &fakeIPv6{fail: step})

			conn, err := rawTransport{}.Open(seamIface.Name, FamilyIPv6, netip.MustParseAddr("fe80::2"))
			requireSeamErr(t, err, step)
			assert.Nil(t, conn)
			assert.Equal(t, 1, pc.closed)
		})
	}
}

func TestRawTransport_OpenReportsAFailedListen(t *testing.T) {
	call := stubTransport(t, nil, &fakeIPv4{}, nil)

	conn, err := rawTransport{}.Open(seamIface.Name, FamilyIPv4, netip.MustParseAddr("192.0.2.2"))
	requireSeamErr(t, err, "ListenPacket")
	assert.Nil(t, conn)
	assert.Equal(t, "ip4:112", call.network)
}

func TestRawConn_SendIPv4CarriesTheSourceAddress(t *testing.T) {
	v4 := &fakeIPv4{}
	c := &rawConn{pc: &fakePacketConn{}, v4: v4, src: net.IP{192, 0, 2, 2}}

	require.NoError(t, c.Send([]byte("advert"), netip.MustParseAddr("224.0.0.18")))
	assert.Equal(t, []byte("advert"), v4.payload)
	assert.Equal(t, &ipv4.ControlMessage{Src: net.IP{192, 0, 2, 2}}, v4.cm)
	assert.Equal(t, &net.IPAddr{IP: net.IP{224, 0, 0, 18}}, v4.dst)
}

func TestRawConn_SendIPv6WritesToTheGroup(t *testing.T) {
	v6 := &fakeIPv6{}
	c := &rawConn{pc: &fakePacketConn{}, v6: v6}

	require.NoError(t, c.Send([]byte("advert"), netip.MustParseAddr("ff02::12")))
	assert.Equal(t, []byte("advert"), v6.payload)
	assert.Nil(t, v6.cm)
	assert.Equal(t, &net.IPAddr{IP: net.ParseIP("ff02::12")}, v6.dst)
}

func TestRawConn_SendIPv6ReportsAWriteFailure(t *testing.T) {
	c := &rawConn{pc: &fakePacketConn{}, v6: &fakeIPv6{fail: "WriteTo"}}

	requireSeamErr(t, c.Send([]byte("advert"), netip.MustParseAddr("ff02::12")), "WriteTo")
}

func TestRawConn_ReceiveIPv6ReportsPayloadSenderAndHopLimit(t *testing.T) {
	pc := &fakePacketConn{}
	v6 := &fakeIPv6{
		read:     []byte("advert"),
		readCM:   &ipv6.ControlMessage{HopLimit: RequiredTTL},
		readFrom: &net.IPAddr{IP: net.ParseIP("fe80::1")},
	}
	c := &rawConn{pc: pc, v6: v6}
	deadline := time.Unix(1700000000, 0)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancel)

	payload, from, hop, err := c.Receive(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("advert"), payload)
	assert.Equal(t, netip.MustParseAddr("fe80::1"), from)
	assert.Equal(t, RequiredTTL, hop)
	assert.True(t, pc.readDeadline.Equal(deadline))
}

func TestRawConn_ReceiveIPv6WithoutAControlMessageReportsHopLimitZero(t *testing.T) {
	v6 := &fakeIPv6{read: []byte("advert"), readFrom: &net.IPAddr{IP: net.ParseIP("fe80::1")}}
	c := &rawConn{pc: &fakePacketConn{}, v6: v6}

	_, _, hop, err := c.Receive(context.Background())
	require.NoError(t, err)
	assert.Zero(t, hop)
}

func TestRawConn_ReceiveIPv6ReportsAReadFailure(t *testing.T) {
	c := &rawConn{pc: &fakePacketConn{}, v6: &fakeIPv6{fail: "ReadFrom"}}

	payload, from, hop, err := c.Receive(context.Background())
	requireSeamErr(t, err, "ReadFrom")
	assert.Nil(t, payload)
	assert.False(t, from.IsValid())
	assert.Zero(t, hop)
}

// addrCall records the link and address a netlink seam was given.
type addrCall struct {
	link vnl.Link
	addr *vnl.Addr
}

// stubNetlink routes the handle-less netlink calls to fakes that fail
// with replaceErr or delErr.
func stubNetlink(t *testing.T, replaceErr, delErr error) (replaced, deleted *addrCall) {
	t.Helper()
	origLink, origReplace, origDel := netlinkLinkByName, netlinkAddrReplace, netlinkAddrDel
	t.Cleanup(func() { netlinkLinkByName, netlinkAddrReplace, netlinkAddrDel = origLink, origReplace, origDel })
	replaced, deleted = &addrCall{}, &addrCall{}
	netlinkLinkByName = func(name string) (vnl.Link, error) {
		if name != seamIface.Name {
			return nil, &errSeam{step: "LinkByName"}
		}
		return &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: name, Index: seamIface.Index}}, nil
	}
	netlinkAddrReplace = func(link vnl.Link, addr *vnl.Addr) error {
		replaced.link, replaced.addr = link, addr
		return replaceErr
	}
	netlinkAddrDel = func(link vnl.Link, addr *vnl.Addr) error {
		deleted.link, deleted.addr = link, addr
		return delErr
	}
	return replaced, deleted
}

func TestNetlinkProgrammer_AddAddressReplacesTheVirtualAddress(t *testing.T) {
	replaced, _ := stubNetlink(t, nil, nil)

	err := NewNetlinkProgrammer().AddAddress(seamIface.Name, netip.MustParsePrefix("192.0.2.1/24"), nil)
	require.NoError(t, err)
	require.NotNil(t, replaced.addr)
	assert.Equal(t, "192.0.2.1/24", replaced.addr.IPNet.String())
	assert.Equal(t, seamIface.Index, replaced.link.Attrs().Index)
}

func TestNetlinkProgrammer_AddAddressReportsFailures(t *testing.T) {
	stubNetlink(t, &errSeam{step: "AddrReplace"}, nil)
	p := NewNetlinkProgrammer()

	requireSeamErr(t, p.AddAddress(seamIface.Name, netip.MustParsePrefix("192.0.2.1/24"), nil), "AddrReplace")
	requireSeamErr(t, p.AddAddress("missing0", netip.MustParsePrefix("192.0.2.1/24"), nil), "LinkByName")
}

func TestNetlinkProgrammer_DeleteAddressRemovesTheVirtualAddress(t *testing.T) {
	_, deleted := stubNetlink(t, nil, nil)

	err := NewNetlinkProgrammer().DeleteAddress(seamIface.Name, netip.MustParsePrefix("2001:db8::1/64"), nil)
	require.NoError(t, err)
	require.NotNil(t, deleted.addr)
	assert.Equal(t, "2001:db8::1/64", deleted.addr.IPNet.String())
}

func TestNetlinkProgrammer_DeleteAddressTreatsAnAbsentAddressAsDone(t *testing.T) {
	stubNetlink(t, nil, unix.EADDRNOTAVAIL)

	assert.NoError(t, NewNetlinkProgrammer().DeleteAddress(seamIface.Name, netip.MustParsePrefix("192.0.2.1/24"), nil))
}

func TestNetlinkProgrammer_DeleteAddressReportsFailures(t *testing.T) {
	stubNetlink(t, nil, &errSeam{step: "AddrDel"})
	p := NewNetlinkProgrammer()

	requireSeamErr(t, p.DeleteAddress(seamIface.Name, netip.MustParsePrefix("192.0.2.1/24"), nil), "AddrDel")
	requireSeamErr(t, p.DeleteAddress("missing0", netip.MustParsePrefix("192.0.2.1/24"), nil), "LinkByName")
}

// stubAddrList routes the handle-less AddrList to a fake that lists addrs
// (or fails with listErr) and records the family it was asked for.
func stubAddrList(t *testing.T, listErr error, addrs ...string) *int {
	t.Helper()
	stubNetlink(t, nil, nil)
	orig := netlinkAddrList
	t.Cleanup(func() { netlinkAddrList = orig })
	family := new(int)
	netlinkAddrList = func(_ vnl.Link, fam int) ([]vnl.Addr, error) {
		*family = fam
		if listErr != nil {
			return nil, listErr
		}
		var out []vnl.Addr
		for _, a := range addrs {
			parsed, err := vnl.ParseAddr(a)
			require.NoError(t, err)
			out = append(out, *parsed)
		}
		return out, nil
	}
	return family
}

func TestNetlinkProgrammer_HasAddressMatchesAddressAndLength(t *testing.T) {
	family := stubAddrList(t, nil, "192.0.2.9/24", "192.0.2.1/24")
	p := NewNetlinkProgrammer().(AddressReader)

	ok, err := p.HasAddress(seamIface.Name, netip.MustParsePrefix("192.0.2.1/24"))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, vnl.FAMILY_V4, *family)

	ok, err = p.HasAddress(seamIface.Name, netip.MustParsePrefix("192.0.2.1/32"))
	require.NoError(t, err)
	assert.False(t, ok, "another prefix length is not the same address")

	ok, err = p.HasAddress(seamIface.Name, netip.MustParsePrefix("192.0.2.2/24"))
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestNetlinkProgrammer_HasAddressAsksForTheIPv6Family(t *testing.T) {
	family := stubAddrList(t, nil, "2001:db8::1/64")
	ok, err := NewNetlinkProgrammer().(AddressReader).HasAddress(seamIface.Name, netip.MustParsePrefix("2001:db8::1/64"))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, vnl.FAMILY_V6, *family)
}

func TestNetlinkProgrammer_HasAddressReportsFailures(t *testing.T) {
	stubAddrList(t, &errSeam{step: "AddrList"})
	p := NewNetlinkProgrammer().(AddressReader)

	_, err := p.HasAddress(seamIface.Name, netip.MustParsePrefix("192.0.2.1/24"))
	requireSeamErr(t, err, "AddrList")
	_, err = p.HasAddress("missing0", netip.MustParsePrefix("192.0.2.1/24"))
	requireSeamErr(t, err, "LinkByName")
}

// fakeFrameWriter records the frame the gratuitous ARP writes.
type fakeFrameWriter struct {
	fail   string
	frame  []byte
	dst    net.Addr
	closed int
}

func (f *fakeFrameWriter) WriteTo(b []byte, addr net.Addr) (int, error) {
	f.frame, f.dst = append([]byte(nil), b...), addr
	return len(b), failAt(f.fail, "WriteTo")
}
func (f *fakeFrameWriter) Close() error { f.closed++; return nil }

// stubARP makes listenARP hand out w, or fail when w is nil.
func stubARP(t *testing.T, w *fakeFrameWriter) {
	t.Helper()
	stubInterface(t)
	orig := listenARP
	t.Cleanup(func() { listenARP = orig })
	listenARP = func(ifi *net.Interface) (frameWriter, error) {
		if w == nil {
			return nil, &errSeam{step: "ListenARP"}
		}
		return w, nil
	}
}

func TestNetlinkProgrammer_AnnounceSendsAGratuitousARP(t *testing.T) {
	w := &fakeFrameWriter{}
	stubARP(t, w)

	require.NoError(t, NewNetlinkProgrammer().Announce(seamIface.Name, netip.MustParseAddr("192.0.2.1"), nil))

	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	assert.Equal(t, &packet.Addr{HardwareAddr: bcast}, w.dst)
	require.GreaterOrEqual(t, len(w.frame), 42)
	assert.Equal(t, []byte(bcast), w.frame[0:6], "Ethernet destination")
	assert.Equal(t, []byte(seamIface.HardwareAddr), w.frame[6:12], "Ethernet source")
	assert.Equal(t, []byte{0x08, 0x06}, w.frame[12:14], "EtherType ARP")
	assert.Equal(t, []byte{0x00, 0x02}, w.frame[20:22], "ARP reply")
	assert.Equal(t, []byte(seamIface.HardwareAddr), w.frame[22:28], "sender hardware address")
	assert.Equal(t, []byte{192, 0, 2, 1}, w.frame[28:32], "sender protocol address")
	assert.Equal(t, []byte{192, 0, 2, 1}, w.frame[38:42], "target protocol address")
	assert.Equal(t, 1, w.closed)
}

func TestNetlinkProgrammer_AnnounceReportsARPFailures(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.1")

	t.Run("listen", func(t *testing.T) {
		stubARP(t, nil)
		requireSeamErr(t, NewNetlinkProgrammer().Announce(seamIface.Name, addr, nil), "ListenARP")
	})
	t.Run("write", func(t *testing.T) {
		w := &fakeFrameWriter{fail: "WriteTo"}
		stubARP(t, w)
		requireSeamErr(t, NewNetlinkProgrammer().Announce(seamIface.Name, addr, nil), "WriteTo")
		assert.Equal(t, 1, w.closed)
	})
	t.Run("interface", func(t *testing.T) {
		stubARP(t, &fakeFrameWriter{})
		requireSeamErr(t, NewNetlinkProgrammer().Announce("missing0", addr, nil), "InterfaceByName")
	})
}

// fakeCloser records that the ICMPv6 socket was closed.
type fakeCloser struct{ closed int }

func (f *fakeCloser) Close() error { f.closed++; return nil }

// stubNA makes listenICMPv6 hand out v6, or fail when v6 is nil.
func stubNA(t *testing.T, v6 *fakeIPv6) *fakeCloser {
	t.Helper()
	stubInterface(t)
	orig := listenICMPv6
	t.Cleanup(func() { listenICMPv6 = orig })
	closer := &fakeCloser{}
	listenICMPv6 = func() (io.Closer, ipv6Conn, error) {
		if v6 == nil {
			return nil, nil, &errSeam{step: "ListenICMPv6"}
		}
		return closer, v6, nil
	}
	return closer
}

func TestNetlinkProgrammer_AnnounceSendsAnUnsolicitedNA(t *testing.T) {
	v6 := &fakeIPv6{}
	closer := stubNA(t, v6)
	target := netip.MustParseAddr("2001:db8::1")

	require.NoError(t, NewNetlinkProgrammer().Announce(seamIface.Name, target, nil))

	assert.Equal(t, RequiredTTL, v6.hop)
	assert.Equal(t, RequiredTTL, v6.mhop)
	assert.Same(t, seamIface, v6.ifi)
	assert.Equal(t, &ipv6.ControlMessage{HopLimit: RequiredTTL, IfIndex: seamIface.Index}, v6.cm)
	assert.Equal(t, &net.IPAddr{IP: net.ParseIP("ff02::1"), Zone: seamIface.Name}, v6.dst)
	require.Len(t, v6.payload, 4+4+16+8)
	assert.Equal(t, byte(136), v6.payload[0], "ICMPv6 Neighbor Advertisement")
	assert.Zero(t, v6.payload[1], "code")
	assert.Equal(t, []byte{0x20, 0, 0, 0}, v6.payload[4:8], "override flag")
	assert.Equal(t, target.AsSlice(), v6.payload[8:24], "target address")
	assert.Equal(t, []byte{2, 1}, v6.payload[24:26], "target link-layer address option")
	assert.Equal(t, []byte(seamIface.HardwareAddr), v6.payload[26:32])
	assert.Equal(t, 1, closer.closed)
}

func TestNetlinkProgrammer_AnnounceReportsNAFailures(t *testing.T) {
	target := netip.MustParseAddr("2001:db8::1")
	for _, step := range []string{"SetHopLimit", "SetMulticastHopLimit", "SetMulticastInterface", "WriteTo"} {
		t.Run(step, func(t *testing.T) {
			closer := stubNA(t, &fakeIPv6{fail: step})
			requireSeamErr(t, NewNetlinkProgrammer().Announce(seamIface.Name, target, nil), step)
			assert.Equal(t, 1, closer.closed)
		})
	}
	t.Run("listen", func(t *testing.T) {
		stubNA(t, nil)
		requireSeamErr(t, NewNetlinkProgrammer().Announce(seamIface.Name, target, nil), "ListenICMPv6")
	})
}

// fakeNetConn adds the net.Conn methods x/net's packet conns require.
type fakeNetConn struct{ fakePacketConn }

func (f *fakeNetConn) Read([]byte) (int, error)  { return 0, io.EOF }
func (f *fakeNetConn) Write([]byte) (int, error) { return 0, io.EOF }
func (f *fakeNetConn) RemoteAddr() net.Addr      { return &net.IPAddr{} }

// TestSeams_DefaultToTheHostCalls guards the production path: a seam left
// pointing at a fake would turn every daemon socket into a no-op.
func TestSeams_DefaultToTheHostCalls(t *testing.T) {
	_, err := interfaceByName("fhrp-missing0")
	assert.Error(t, err)
	assert.IsType(t, &ipv4.PacketConn{}, newIPv4Conn(&fakeNetConn{}))
	assert.IsType(t, &ipv6.PacketConn{}, newIPv6Conn(&fakeNetConn{}))
}

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
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The kernel-facing paths are exercised end to end by
// test/integration/sdn/fhrp_netns_test.go (root, NET_ADMIN, NET_RAW). What
// can be proven without privileges is that every entry point fails closed
// on an interface that does not exist and that the constructor options
// take effect.

func TestNetlinkProgrammer_UnknownInterfaceFailsClosed(t *testing.T) {
	hw := VirtualMAC(FamilyIPv4, 7)
	pfx := netip.MustParsePrefix("10.99.0.1/24")
	for name, p := range map[string]Programmer{
		"default handle": NewNetlinkProgrammer(),
		"explicit handle": func() Programmer {
			h, err := vnl.NewHandle()
			require.NoError(t, err)
			t.Cleanup(h.Close)
			return NewNetlinkProgrammer(WithNetlinkHandle(h))
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, p.AddAddress("no-such-if-585", pfx, hw))
			require.Error(t, p.DeleteAddress("no-such-if-585", pfx, hw))
			require.Error(t, p.Announce("no-such-if-585", pfx.Addr(), hw))
			require.Error(t, p.Announce("no-such-if-585", netip.MustParseAddr("fd00::1"), hw))
		})
	}
}

func TestRawTransport_UnknownInterfaceFailsClosed(t *testing.T) {
	_, err := NewRawTransport().Open("no-such-if-585", FamilyIPv4, netip.MustParseAddr("10.99.0.2"))
	require.Error(t, err)
	_, err = NewRawTransport().Open("no-such-if-585", FamilyIPv6, netip.MustParseAddr("fd00::2"))
	require.Error(t, err)
}

// failingRawConn is a syscall.RawConn whose Control never reaches the fd.
type failingRawConn struct{ err error }

func (f failingRawConn) Control(func(uintptr)) error    { return f.err }
func (f failingRawConn) Read(func(uintptr) bool) error  { return f.err }
func (f failingRawConn) Write(func(uintptr) bool) error { return f.err }

func loopbackRawConn(t *testing.T) syscall.RawConn {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })
	rc, err := pc.(*net.UDPConn).SyscallConn()
	require.NoError(t, err)
	return rc
}

func TestBindToDevice_ScopesTheSocketToTheInterface(t *testing.T) {
	rc := loopbackRawConn(t)
	require.NoError(t, bindToDevice(rc, "lo"))
	var bound string
	var sockErr error
	require.NoError(t, rc.Control(func(fd uintptr) {
		bound, sockErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}))
	require.NoError(t, sockErr)
	assert.Equal(t, "lo", bound)
}

func TestBindToDevice_ReportsFailures(t *testing.T) {
	require.Error(t, bindToDevice(loopbackRawConn(t), "no-such-if-596"), "an unknown interface is refused")
	assert.ErrorIs(t, bindToDevice(failingRawConn{err: syscall.EBADF}, "lo"), syscall.EBADF, "a socket that cannot be reached is refused")
}

func TestAddrOf(t *testing.T) {
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), addrOf(&net.IPAddr{IP: net.ParseIP("10.0.0.1")}))
	assert.Equal(t, netip.MustParseAddr("fd00::1"), addrOf(&net.IPAddr{IP: net.ParseIP("fd00::1")}))
	assert.False(t, addrOf(&net.UDPAddr{}).IsValid(), "a non-IPAddr yields the zero address")
}

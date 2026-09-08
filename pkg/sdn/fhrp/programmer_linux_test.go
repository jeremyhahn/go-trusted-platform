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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
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

func TestAddrOf(t *testing.T) {
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), addrOf(&net.IPAddr{IP: net.ParseIP("10.0.0.1")}))
	assert.Equal(t, netip.MustParseAddr("fd00::1"), addrOf(&net.IPAddr{IP: net.ParseIP("fd00::1")}))
	assert.False(t, addrOf(&net.UDPAddr{}).IsValid(), "a non-IPAddr yields the zero address")
}
